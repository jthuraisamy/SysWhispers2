#!/usr/bin/python3

import argparse
import json
import os
import random
import struct


class SysWhispers(object):
    def __init__(self, function_prefix):
        self.__function_prefix = function_prefix

        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.typedefs: list = json.load(open(os.path.join(os.path.dirname(__file__), "data", "typedefs.json")))
        self.prototypes: dict = json.load(open(os.path.join(os.path.dirname(__file__), "data", "prototypes.json")))
        self.arch_list = self._parse_arch()
        self.asm_list = self._parse_asm_type()
        self.asm_code = {
            'x86': { 
                'masm': {
                    'std': b'''.686
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

''',
                    'rnd': b'''.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data
stubReturn      dd 0
returnAddress   dd 0
espBookmark     dd 0
syscallNumber   dd 0
syscallAddress  dd 0

.code

EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC

WhisperMain PROC
    pop eax                                 ; Remove return address from CALL instruction
    mov dword ptr [stubReturn], eax         ; Save the return address to the stub
    push esp
    pop eax
    add eax, 04h
    push dword ptr [eax]
    pop returnAddress                       ; Save the original return address
    add eax, 04h
    push eax
    pop espBookmark                         ; Save original ESP
    call SW2_GetSyscallNumber               ; Resolve function hash into syscall number
    add esp, 4                              ; Restore ESP
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor eax, eax
    mov ecx, fs:[0c0h]
    test ecx, ecx
    je _x86
    inc eax
_x86: 
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+04h]
    call SW2_GetRandomSyscallAddress        ; Get a memory address of random syscall
    mov dword ptr [syscallAddress], eax     ; Save the address
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    mov eax, dword ptr [syscallNumber]      ; Restore the syscall number
    call dword ptr syscallAddress           ; Call the random syscall
    mov esp, dword ptr [espBookmark]        ; Restore ESP
    push dword ptr [returnAddress]          ; Restore the return address
    ret
WhisperMain ENDP

''',
                    'func': b'''{function_name} PROC
    push 0{function_hash:08X}h
    call WhisperMain
{function_name} ENDP
'''
                },
                'nasm': {
                    'std': b'''[SECTION .data]

{globalFunctions}
global _WhisperMain
extern _SW2_GetSyscallNumber

[SECTION .text]

BITS 32
DEFAULT REL

_WhisperMain:
    pop eax                        ; Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, [fs:0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword [fs:0c0h]
    ret

''',
                    'rnd': b'''[SECTION .data align=4]
stubReturn:     dd  0
returnAddress:  dd  0
espBookmark:    dd  0
syscallNumber:  dd  0
syscallAddress: dd  0

[SECTION .text]

BITS 32
DEFAULT REL

{globalFunctions}
global _WhisperMain
extern _SW2_GetSyscallNumber
extern _SW2_GetRandomSyscallAddress

_WhisperMain:
    pop eax                                  
    mov dword [stubReturn], eax             ; Save the return address to the stub
    push esp
    pop eax
    add eax, 4h
    push dword [eax]
    pop dword [returnAddress]               ; Save original return address
    add eax, 4h
    push eax
    pop dword [espBookmark]                 ; Save original ESP
    call _SW2_GetSyscallNumber              ; Resolve function hash into syscall number
    add esp, 4h                             ; Restore ESP
    mov dword [syscallNumber], eax          ; Save the syscall number
    xor eax, eax
    mov ecx, dword [fs:0c0h]
    test ecx, ecx
    je _x86
    inc eax                                 ; Inc EAX to 1 for Wow64
_x86:
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword [esp+4h]
    call _SW2_GetRandomSyscallAddress       ; Get a random 0x02E address
    mov dword [syscallAddress], eax         ; Save the address
    mov esp, dword [espBookmark]            ; Restore ESP
    mov eax, dword [syscallNumber]          ; Restore the syscall number
    call dword [syscallAddress]             ; Call the random syscall location
    mov esp, dword [espBookmark]            ; Restore ESP
    push dword [returnAddress]              ; Restore the return address
    ret
    
''',
                    'func': b'''_{function_name}:
    push 0{function_hash:08X}h
    call _WhisperMain
'''
                },
                'gas': {
                    'std': b'''.intel_syntax noprefix

.text
{globalFunctions}
.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
    ret

''',
                    'rnd': b'''.intel_syntax noprefix
.data
.align 4
stubReturn:     .long 0
returnAddress:  .long 0
espBookmark:    .long 0
syscallNumber:  .long 0
syscallAddress: .long 0

.text
{globalFunctions}
.global _WhisperMain

_WhisperMain:
    pop eax                                  
    mov dword ptr [stubReturn], eax         # Save the return address to the stub
    push esp
    pop eax
    add eax, 0x04
    push [eax]
    pop returnAddress                       # Save original return address
    add eax, 0x04
    push eax
    pop espBookmark                         # Save original ESP
    call _SW2_GetSyscallNumber              # Resolve function hash into syscall number
    add esp, 4                              # Restore ESP
    mov dword ptr [syscallNumber], eax      # Save the syscall number
    xor eax, eax
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    je _x86
    inc eax                                 # Inc EAX to 1 for Wow64
_x86:
    push eax                                # Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+0x04]
    call _SW2_GetRandomSyscallAddress       # Get a random 0x02E address
    mov dword ptr [syscallAddress], eax     # Save the address
    mov esp, dword ptr [espBookmark]        # Restore ESP
    mov eax, dword ptr [syscallNumber]      # Restore the syscall number
    call dword ptr syscallAddress           # Call the random syscall location
    mov esp, dword ptr [espBookmark]        # Restore ESP
    push dword ptr [returnAddress]          # Restore the return address
    ret

''',
                    'func': b'''_{function_name}:
    push 0x{function_hash:08X}
    call _WhisperMain
'''
                },
                'inlinegas': {
                    'std': b'''#define WhisperMain
__asm__(".intel_syntax noprefix \\n\\
.global _WhisperMain \\n\\
_WhisperMain: \\n\\
    pop eax \\n\\
    call _SW2_GetSyscallNumber \\n\\
    add esp, 4 \\n\\
    mov ecx, dword ptr fs:0xc0 \\n\\
    test ecx, ecx \\n\\
    jne _wow64 \\n\\
    lea edx, dword ptr [esp+0x04] \\n\\
    INT 0x02e \\n\\
    ret \\n\\
_wow64: \\n\\
    xor ecx, ecx \\n\\
    lea edx, dword ptr [esp+0x04] \\n\\
    call dword ptr fs:0xc0 \\n\\
    ret \\n\\
");

''',
                    'rnd': b'''DWORD stubReturn = 0;
DWORD returnAddress = 0;
DWORD espBookmark = 0;
DWORD syscallNumber = 0;
DWORD syscallAddress = 0;

__declspec(naked) void WhisperMain(void)
{
    __asm__(".intel_syntax noprefix \\n\\
    .global _WhisperMain \\n\\
    _WhisperMain: \\n\\
        pop eax \\n\\
        mov dword ptr [%[stubReturn]], eax \\n\\
        push esp \\n\\
        pop eax \\n\\
        add eax, 0x04 \\n\\
        push [eax] \\n\\
        pop %[returnAddress] \\n\\
        add eax, 0x04 \\n\\
        push eax \\n\\
        pop %[espBookmark] \\n\\
        call _SW2_GetSyscallNumber \\n\\
        add esp, 4 \\n\\
        mov dword ptr [%[syscallNumber]], eax \\n\\
        xor eax, eax \\n\\
        mov ecx, dword ptr fs:0xc0 \\n\\
        test ecx, ecx \\n\\
        je _x86 \\n\\
        inc eax \\n\\
    _x86: \\n\\
        push eax \\n\\
        lea edx, dword ptr [esp+0x04] \\n\\
        call _SW2_GetRandomSyscallAddress \\n\\
        mov dword ptr [%[syscallAddress]], eax \\n\\
        mov esp, dword ptr [%[espBookmark]] \\n\\
        mov eax, dword ptr [%[syscallNumber]] \\n\\
        call dword ptr %[syscallAddress] \\n\\
        mov esp, dword ptr [%[espBookmark]] \\n\\
        push dword ptr [%[returnAddress]] \\n\\
        ret \\n\\
    "
    : [stubReturn] "+m" (stubReturn), [returnAddress] "+m" (returnAddress), [espBookmark] "+m" (espBookmark), [syscallNumber] "+m" (syscallNumber), [syscallAddress] "+m" (syscallAddress)
    :
    :
    );
}

''',
                    'func': b'''#define Zw{function_name} Nt{function_name}
__asm__(".intel_syntax noprefix \\n\\
_Nt{function_name}: \\n\\
    push 0x{function_hash:08X} \\n\\
    call _WhisperMain \\n\\
");

'''
                }
            },
            'x64': {
                'masm': {
                    'std': b'''.data
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

''',
                    'rnd': b'''.data
currentHash     dd  0
returnAddress   dq  0
syscallNumber   dd  0
syscallAddress  dq  0

.code
EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx                       ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress        ; Get a random syscall address
    mov qword ptr [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, syscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]                       ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress]           ; Save the original return address
    call qword ptr [syscallAddress]         ; Call the random syscall instruction
    push qword ptr [returnAddress]          ; Restore the original return address
    ret
WhisperMain ENDP

''',
                    'func': b'''{function_name} PROC
    mov currentHash, 0{function_hash:08X}h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
{function_name} ENDP
'''
                },
                'nasm': {
                    'std': b'''[SECTION .data]
currentHash:    dd  0

[SECTION .text]

BITS 64
DEFAULT REL

{globalFunctions}
global WhisperMain
extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret

''',
                    'rnd': b'''[SECTION .data]
currentHash:    dd  0
returnAddress:  dq  0
syscallNumber:  dd  0
syscallAddress: dq  0

[SECTION .text]

BITS 64
DEFAULT REL

{globalFunctions}
global WhisperMain
extern SW2_GetSyscallNumber
extern SW2_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                   ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    mov dword [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress    ; Get a random syscall address
    mov qword [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, dword [syscallNumber]      ; Restore the syscall value
    add rsp, 28h
    mov rcx, [rsp+ 8]                   ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword [returnAddress]           ; Save the original return address
    call qword [syscallAddress]         ; Issue syscall
    push qword [returnAddress]          ; Restore the original return address
    ret

''',
                    'func': b'''{function_name}:
    mov dword [currentHash], 0{function_hash:08X}h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call
'''
                },
                'gas': {
                    'std': b'''.intel_syntax noprefix
.data
currentHash:    .long   0

.text
{globalFunctions}
.global WhisperMain
.extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    add rsp, 0x28
    mov rcx, [rsp+ 8]              # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        # Issue syscall
    ret

''',
                    'rnd': b'''.intel_syntax noprefix
.data
currentHash:    .long   0
returnAddress:  .quad   0
syscallNumber:  .long   0
syscallAddress: .quad   0

.text
{globalFunctions}
.global WhisperMain
.extern SW2_GetSyscallNumber
.extern SW2_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                           # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber + RIP], eax    # Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress            # Get a random syscall address
    mov qword ptr [syscallAddress + RIP], rax   # Save the random syscall address
    xor rax, rax
    mov eax, dword ptr [syscallNumber + RIP]    # Restore the syscall vallue
    add rsp, 0x28
    mov rcx, [rsp+ 8]                           # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress + RIP]         # Save the original return address
    call qword ptr [syscallAddress + RIP]       # Issue syscall
    push qword ptr [returnAddress + RIP]        # Restore the original return address
    ret

''',
                    'func': b'''{function_name}:
    mov dword ptr [currentHash + RIP], 0x0{function_hash:08X}   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call

'''
                },
                'inlinegas': {
                    'std': b'''#define WhisperMain
__asm__(".intel_syntax noprefix \\n\\
.global WhisperMain \\n\\
WhisperMain: \\n\\
    pop rax \\n\\
    mov [rsp+ 8], rcx \\n\\
    mov [rsp+16], rdx \\n\\
    mov [rsp+24], r8 \\n\\
    mov [rsp+32], r9 \\n\\
    sub rsp, 0x28 \\n\\
    mov rcx, r10 \\n\\
    call SW2_GetSyscallNumber \\n\\
    add rsp, 0x28 \\n\\
    mov rcx, [rsp+ 8] \\n\\
    mov rdx, [rsp+16] \\n\\
    mov r8, [rsp+24] \\n\\
    mov r9, [rsp+32] \\n\\
    mov r10, rcx \\n\\
    syscall \\n\\
    ret \\n\\
");

''',
                    'rnd': b'''DWORD currentHash = 0;
uint64_t returnAddress = 0;
DWORD syscallNumber = 0;
uint64_t syscallAddress = 0;

__declspec(naked) void WhisperMain(void)
{
__asm__(".intel_syntax noprefix \n\
    .global WhisperMain \n\
    WhisperMain: \n\
        pop rax \n\
        mov [rsp+ 8], rcx \n\
        mov [rsp+16], rdx \n\
        mov [rsp+24], r8 \n\
        mov [rsp+32], r9 \n\
        sub rsp, 0x28 \n\
        mov rcx, r10 \n\
        call SW2_GetSyscallNumber \n\
        mov dword ptr [syscallNumber + RIP], eax  \n\
        xor rcx, rcx \n\
        call SW2_GetRandomSyscallAddress \n\
        mov qword ptr [syscallAddress + RIP], rax \n\
        xor rax, rax \n\
        mov eax, dword ptr [syscallNumber + RIP] \n\
        add rsp, 0x28 \n\
        mov rcx, [rsp+ 8] \n\
        mov rdx, [rsp+16] \n\
        mov r8, [rsp+24] \n\
        mov r9, [rsp+32] \n\
        mov r10, rcx \n\
        pop qword ptr [returnAddress + RIP] \n\
        call qword ptr [syscallAddress + RIP] \n\
        push qword ptr [returnAddress + RIP] \n\
        ret \n\
    "
    : [returnAddress] "+m" (returnAddress), [syscallNumber] "+m" (syscallNumber), [syscallAddress] "+m" (syscallAddress)
    :
    :
    );
}

''',
                    'func': b'''#define Zw{function_name} Nt{function_name}
__asm__(".intel_syntax noprefix \\n\\
Nt{function_name}: \\n\\
    mov r10, 0x0{function_hash:08X} \\n\\
    call WhisperMain \\n\\
");

'''
                }
            }
        }
                
    def generate(self, function_names: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        elif any([f not in self.prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Change default function prefix.
        if self.__function_prefix != 'Nt':
            new_function_names = []
            for function_name in function_names:
                new_function_name = function_name.replace('Nt', self.__function_prefix, 1)
                if new_function_name != function_name:
                    self.prototypes[new_function_name] = self.prototypes[function_name]
                    del self.prototypes[function_name]
                new_function_names.append(new_function_name)

            function_names = new_function_names

        # Write C file.
        with open (os.path.join(os.path.dirname(__file__), "data", "base.c"), 'rb') as base_source:
            with open(f'{basename}.c', 'wb') as output_source:
                base_source_contents = base_source.read().decode()
                base_source_contents = base_source_contents.replace('<BASENAME>', os.path.basename(basename), 1)
                output_source.write(base_source_contents.encode())


        # Write header file.
        with open(os.path.join(os.path.dirname(__file__), "data", "base.h"), 'rb') as base_header:
            with open(f'{basename}.h', 'wb') as output_header:
                # Replace <SEED_VALUE> with a random seed.
                base_header_contents = base_header.read().decode()
                base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.seed:08X}', 1)
                base_header_contents = base_header_contents.replace('\r','')

                # Write the base header.
                output_header.write(base_header_contents.encode())

                # Write the typedefs.
                for typedef in self._get_typedefs(function_names):
                    output_header.write(typedef.replace('\r','').encode() + b'\n\n')

                # Write the function prototypes.
                for function_name in function_names:
                    output_header.write((self._get_function_prototype(function_name).replace('\r','') + '\n\n').encode())

                # Write the endif line.
                output_header.write('#endif\n'.encode())

        print('Complete! Files written to:')
        print(f'\t{basename}.h')
        print(f'\t{basename}.c')
        
        for arch in self.arch_list:
            for lang in self.asm_list:
                self._gen_asm_file(arch, lang, basename, function_names)
        
    def _gen_asm_file(self, arch, lang, basename, function_names):
        for callType in ['std', 'rnd']:
            # Set the file extension
            if lang == 'masm':
                file_ext = 'asm'
            elif lang == 'nasm':
                file_ext = 'nasm'
            elif lang == 'gas':
                file_ext = 's'
            elif lang == 'inlinegas':
                file_ext = 'h'
                
            # Write ASM file.
            if lang == 'inlinegas':
                basename_suffix = 'inline'
            else:
                basename_suffix = 'stubs'
            basename_suffix = basename_suffix.capitalize() if os.path.basename(basename).istitle() else basename_suffix
            basename_suffix = f'_{basename_suffix}' if '_' in basename else basename_suffix
            with open(f'{basename}{basename_suffix}.{callType}.{arch}.{file_ext}', 'wb') as output_asm:
                # Add the stub
                if lang == 'masm':
                    output_asm.write(self.asm_code[arch][lang][callType])
                elif lang == 'inlinegas':
                    with open(f'{basename}.h', 'rb') as tempFile:
                        output_asm.write(tempFile.read())
                        output_asm.write(b'\n\n')
                    with open(f'{basename}.c', 'rb') as tempFile:
                        cBase = tempFile.read()
                        cBase = cBase.decode().replace(f'#include "{basename}.h"','').encode()
                        output_asm.write(cBase)
                        output_asm.write(b'\n\n')
                    output_asm.write(self.asm_code[arch][lang][callType])
                else:
                    globalFunctions = ''
                    for function_name in function_names:
                        if lang == 'nasm':
                            if arch == 'x64':
                                globalFunctions = globalFunctions + 'global {function_name}\n'.format(function_name = function_name)
                            else:
                                globalFunctions = globalFunctions + 'global _{function_name}\n'.format(function_name = function_name)
                        else:
                            if arch == 'x64':
                                globalFunctions = globalFunctions + '.global {function_name}\n'.format(function_name = function_name)
                            else:
                                globalFunctions = globalFunctions + '.global _{function_name}\n'.format(function_name = function_name)
                    output_asm.write(self.asm_code[arch][lang][callType].decode().format(globalFunctions = globalFunctions).encode())
                    
                for function_name in function_names:
                    output_asm.write((self._get_function_asm_code(arch, lang, function_name) + '\n').encode())
                if lang == 'masm':
                    output_asm.write(b'end')
                    
            print(f'\t{basename}{basename_suffix}.{callType}.{arch}.{file_ext}')
        
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
        name = function_name.replace(self.__function_prefix, 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)

        return hash

    def _get_function_asm_code(self, arch, lang, function_name: str) -> str:
        function_hash = self._get_function_hash(function_name)
        
        if lang == 'inlinegas':
            return self.asm_code[arch][lang]['func'].decode().format(function_name = function_name[2:], function_hash = function_hash)
        else:
            return self.asm_code[arch][lang]['func'].decode().format(function_name = function_name, function_hash = function_hash)
    
    def _parse_arch(self):
        arch_list = []
        if args.arch:
            if ',' in args.arch:
                raw = args.arch.split(',')
                for arch in raw:
                    if (arch.strip().lower() == 'x86') or (arch.strip().lower() == 'all'):
                        arch_list.append('x86')
                    if (arch.strip().lower() == 'x64') or (arch.strip().lower() == 'all'):
                        arch_list.append('x64')
            else:
                if (args.arch.strip().lower() == 'x86') or (args.arch.strip().lower() == 'all'):
                    arch_list.append('x86')
                if (args.arch.strip().lower() == 'x64') or (args.arch.strip().lower() == 'all'):
                    arch_list.append('x64')
        else:
            # Assume all
            arch_list.append('x86')
            arch_list.append('x64')
        return list(dict.fromkeys(arch_list))
    
    def _parse_asm_type(self):
        asm_list = []
        if args.asm_lang:
            if ',' in args.asm_lang:
                raw = args.asm_lang.split(',')
                for lang in raw:
                    if (lang.strip().lower() == 'masm') or (lang.strip().lower() == 'all'):
                        asm_list.append('masm')
                    if (lang.strip().lower() == 'nasm') or (lang.strip().lower() == 'all'):
                        asm_list.append('nasm')
                    if (lang.strip().lower() == 'gas') or (lang.strip().lower() == 'all'):
                        asm_list.append('gas')
                    if (lang.strip().lower() == 'inlinegas') or (lang.strip().lower() == 'all'):
                        asm_list.append('inlinegas')
            else:
                if (args.asm_lang.strip().lower() == 'masm') or (args.asm_lang.strip().lower() == 'all'):
                    asm_list.append('masm')
                if (args.asm_lang.strip().lower() == 'nasm') or (args.asm_lang.strip().lower() == 'all'):
                    asm_list.append('nasm')
                if (args.asm_lang.strip().lower() == 'gas') or (args.asm_lang.strip().lower() == 'all'):
                    asm_list.append('gas')
                if (args.asm_lang.strip().lower() == 'inlinegas') or (args.asm_lang.strip().lower() == 'all'):
                    asm_list.append('inlinegas')
        else:
            # Assume all
            asm_list.append('masm')
            asm_list.append('nasm')
            asm_list.append('gas')
            asm_list.append('inlinegas')
        return list(dict.fromkeys(asm_list))

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
    parser.add_argument('-a', '--arch', help='CPU architecture ("all", "x86", "x64")', required=False)
    parser.add_argument('-l', '--asm-lang', help='Assembler output format ("all", "masm", "nasm", "gas", "inlinegas")', required=False)
    parser.add_argument('--function-prefix', default='Nt', help='Function prefix', required=False)
    args = parser.parse_args()

    sw = SysWhispers(args.function_prefix)

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
