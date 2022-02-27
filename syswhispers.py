#!/usr/bin/python3

import argparse
import json
import os
import random
import struct


class SysWhispers(object):
    def __init__(self):
        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.typedefs: list = json.load(open(os.path.join(os.path.dirname(__file__), "data", "typedefs.json")))
        self.prototypes: dict = json.load(open(os.path.join(os.path.dirname(__file__), "data", "prototypes.json")))
        self.x86_stub_common = b'''.686 
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

'''
        self.x64_stub_common = b'''.data
currentHash DWORD 0

.code
EXTERN SW2_GetSyscallNumber: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret
WhisperMain ENDP

'''

    def generate(self, function_names: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        elif any([f not in self.prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Write C file.
        with open (os.path.join(os.path.dirname(__file__), "data", "base.c"), 'rb') as base_source:
            with open(f'{basename}.c', 'wb') as output_source:
                base_source_contents = base_source.read().decode()
                base_source_contents = base_source_contents.replace('<BASENAME>', os.path.basename(basename), 1)
                output_source.write(base_source_contents.encode())

        # Write x86 ASM file.
        basename_x86_suffix = 'x86stubs'
        basename_x86_suffix = basename_x86_suffix.capitalize() if os.path.basename(basename).istitle() else basename_x86_suffix
        basename_x86_suffix = f'_{basename_x86_suffix}' if '_' in basename else basename_x86_suffix
        with open(f'{basename}{basename_x86_suffix}.asm', 'wb') as output_asm:
            output_asm.write(self.x86_stub_common)
            for function_name in function_names:
                output_asm.write((self._get_function_x86_asm_code(function_name) + '\n').encode())
            output_asm.write(b'end')

        # Write x64 ASM file.
        basename_x64_suffix = 'x64stubs'
        basename_x64_suffix = basename_x64_suffix.capitalize() if os.path.basename(basename).istitle() else basename_x64_suffix
        basename_x64_suffix = f'_{basename_x64_suffix}' if '_' in basename else basename_x64_suffix
        with open(f'{basename}{basename_x64_suffix}.asm', 'wb') as output_asm:
            output_asm.write(self.x64_stub_common)
            for function_name in function_names:
                output_asm.write((self._get_function_x64_asm_code(function_name) + '\n').encode())
            output_asm.write(b'end')
            
        # Write header file.
        with open(os.path.join(os.path.dirname(__file__), "data", "base.h"), 'rb') as base_header:
            with open(f'{basename}.h', 'wb') as output_header:
                # Replace <SEED_VALUE> with a random seed.
                base_header_contents = base_header.read().decode()
                base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.seed:08X}', 1)

                # Write the base header.
                output_header.write(base_header_contents.encode())

                # Write the typedefs.
                for typedef in self._get_typedefs(function_names):
                    output_header.write(typedef.encode() + b'\n\n')

                # Write the function prototypes.
                for function_name in function_names:
                    output_header.write((self._get_function_prototype(function_name) + '\n\n').encode())

                # Write the endif line.
                output_header.write('#endif\n'.encode())

        print('Complete! Files written to:')
        print(f'\t{basename}.h')
        print(f'\t{basename}.c')
        print(f'\t{basename}{basename_x86_suffix}.asm')
        print(f'\t{basename}{basename_x64_suffix}.asm')

    def _get_typedefs(self, function_names: list) -> list:
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.typedefs[typedef_id]['dependencies']
            more_dependencies = list(set(more_dependencies))  # Remove duplicates.

            if more_dependencies:
                # Create new layer.
                i += 1
                typedef_layers[i] = _names_to_ids(more_dependencies)
            else:
                # Remove duplicates between layers.
                for k in range(len(typedef_layers) - 1):
                    typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
                break

        # Get code for each typedef.
        typedef_code = []
        for i in range(max(typedef_layers.keys()), -1, -1):
            for j in typedef_layers[i]:
                typedef_code.append(self.typedefs[j]['definition'])
        return typedef_code

    def _get_function_prototype(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{param["type"]} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature

    def _get_function_hash(self, function_name: str):
        hash = self.seed
        name = function_name.replace('Nt', 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)

        return hash

    def _get_function_x86_asm_code(self, function_name: str) -> str:
        function_hash = self._get_function_hash(function_name)

        # Generate 32-bit ASM code.
        code = f'''{function_name} PROC
    push 0{function_hash:08X}h
    call WhisperMain
{function_name} ENDP
'''

        return code

    def _get_function_x64_asm_code(self, function_name: str) -> str:
        function_hash = self._get_function_hash(function_name)

        # Generate 64-bit ASM code.
        code = f'''{function_name} PROC
    mov currentHash, 0{function_hash:08X}h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
{function_name} ENDP
'''

        return code


if __name__ == '__main__':
    print(
        "                                                 \n"
        "                  .                         ,--. \n"
        ",-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.    / \n"
        "`-. | | `-. |/|/  | | | `-. | | |-' |   `-. ,-'  \n"
        "`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-' `--- \n"
        "     /|                     |  @Jackson_T        \n"
        "    `-'                     '  @modexpblog, 2021 \n\n"
        "SysWhispers2: Why call the kernel when you can whisper?\n"
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    args = parser.parse_args()

    sw = SysWhispers()

    if args.preset == 'all':
        print('All functions selected.\n')
        sw.generate(basename=args.out_file)

    elif args.preset == 'common':
        print('Common functions selected.\n')
        sw.generate(
            ['NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenProcessToken',
             'NtTestAlert',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'],
            basename=args.out_file)

    elif args.preset:
        print('ERROR: Invalid preset provided. Must be "all" or "common".')

    elif not args.functions:
        print('ERROR:   --preset XOR --functions switch must be specified.\n')
        print('EXAMPLE: ./syswhispers.py --preset common --out-file syscalls_common')
        print('EXAMPLE: ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

    else:
        functions = args.functions.split(',') if args.functions else []
        sw.generate(functions, args.out_file)
