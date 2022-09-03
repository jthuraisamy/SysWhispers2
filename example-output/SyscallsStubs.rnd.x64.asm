.data
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

NtAccessCheck PROC
    mov currentHash, 018A0737Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    mov currentHash, 09BA97DB3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    mov currentHash, 068B11B5Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    mov currentHash, 07FEE1137h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    mov currentHash, 090BFA003h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    mov currentHash, 01E941D38h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallbackReturn ENDP

NtReadFile PROC
    mov currentHash, 0EA79D8E0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFile ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 07CF8ADCCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    mov currentHash, 059C9C8FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    mov currentHash, 00E886E1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    mov currentHash, 044960E3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    mov currentHash, 05930A25Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    mov currentHash, 02EBC2B22h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyPort ENDP

NtSetInformationThread PROC
    mov currentHash, 0340FF225h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationThread ENDP

NtSetEvent PROC
    mov currentHash, 008921512h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEvent ENDP

NtClose PROC
    mov currentHash, 04495DDA1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtQueryObject PROC
    mov currentHash, 006286085h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryObject ENDP

NtQueryInformationFile PROC
    mov currentHash, 093356B21h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtOpenKey PROC
    mov currentHash, 0720A7393h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKey ENDP

NtEnumerateValueKey PROC
    mov currentHash, 0DA9ADD04h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateValueKey ENDP

NtFindAtom PROC
    mov currentHash, 0322317BAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    mov currentHash, 011287BAFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    mov currentHash, 0A672CB80h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryKey ENDP

NtQueryValueKey PROC
    mov currentHash, 0982089B9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 0C1512DC6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    mov currentHash, 0519E7C0Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    mov currentHash, 03EAC1F7Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    mov currentHash, 0318CE8A7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFileGather ENDP

NtCreateKey PROC
    mov currentHash, 0104523FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 001930F05h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    mov currentHash, 0396D26E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    mov currentHash, 0BB168A93h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    mov currentHash, 08B9FF70Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    mov currentHash, 020B04558h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    mov currentHash, 079917101h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    mov currentHash, 0FB531910h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    mov currentHash, 0144CD773h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtOpenProcess PROC
    mov currentHash, 0CE2CC5B1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtSetInformationFile PROC
    mov currentHash, 02D7D51A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    mov currentHash, 060C9AE95h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    mov currentHash, 030971C08h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 008E02671h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    mov currentHash, 0756F27B5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    mov currentHash, 0C337DE9Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    mov currentHash, 0D88FCC04h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    mov currentHash, 005AC0D37h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    mov currentHash, 05A433EBEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    mov currentHash, 064B1500Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    mov currentHash, 07BED8581h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    mov currentHash, 0761F6184h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateKey ENDP

NtOpenFile PROC
    mov currentHash, 0EA58F2EAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenFile ENDP

NtDelayExecution PROC
    mov currentHash, 01AB51B26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 0A8E240B0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    mov currentHash, 0228A241Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtOpenSection PROC
    mov currentHash, 08B23AB8Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtQueryTimer PROC
    mov currentHash, 0C99AF150h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimer ENDP

NtFsControlFile PROC
    mov currentHash, 03895E81Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 09B70CDAFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    mov currentHash, 016DB99C4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    mov currentHash, 02C050459h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    mov currentHash, 0A6B5C6B2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAttributesFile ENDP

NtClearEvent PROC
    mov currentHash, 07EA59CF0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearEvent ENDP

NtReadVirtualMemory PROC
    mov currentHash, 03191351Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    mov currentHash, 0183371AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 06DDD5958h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    mov currentHash, 08350ADCCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateToken ENDP

NtContinue PROC
    mov currentHash, 02EA07164h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    mov currentHash, 055D63014h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    mov currentHash, 03CA43609h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtYieldExecution PROC
    mov currentHash, 018B23A23h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtYieldExecution ENDP

NtAddAtom PROC
    mov currentHash, 03FB57C63h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtom ENDP

NtCreateEvent PROC
    mov currentHash, 011B0FFAAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    mov currentHash, 03575CE31h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    mov currentHash, 0249304C1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtFlushBuffersFile PROC
    mov currentHash, 01D5C1AC4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    mov currentHash, 034624AA3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    mov currentHash, 011B3E1CBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcessEx ENDP

NtCreateThread PROC
    mov currentHash, 0922FDC85h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThread ENDP

NtIsProcessInJob PROC
    mov currentHash, 0A8D15C80h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 08792CB57h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    mov currentHash, 01A8C5E27h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySection ENDP

NtResumeThread PROC
    mov currentHash, 06AC0665Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtTerminateThread PROC
    mov currentHash, 02A0B34A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateThread ENDP

NtReadRequestData PROC
    mov currentHash, 02E83F03Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadRequestData ENDP

NtCreateFile PROC
    mov currentHash, 06756F762h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateFile ENDP

NtQueryEvent PROC
    mov currentHash, 08000E5E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEvent ENDP

NtWriteRequestData PROC
    mov currentHash, 0621E52D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    mov currentHash, 02A353AA9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    mov currentHash, 00C53C00Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 051256B89h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    mov currentHash, 03C1704BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationObject ENDP

NtCancelIoFile PROC
    mov currentHash, 008B94C02h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFile ENDP

NtTraceEvent PROC
    mov currentHash, 02EB52126h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceEvent ENDP

NtPowerInformation PROC
    mov currentHash, 06688641Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPowerInformation ENDP

NtSetValueKey PROC
    mov currentHash, 0E9392F67h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetValueKey ENDP

NtCancelTimer PROC
    mov currentHash, 0178326C0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer ENDP

NtSetTimer PROC
    mov currentHash, 01DC52886h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer ENDP

NtAccessCheckByType PROC
    mov currentHash, 0DC56E104h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    mov currentHash, 0C972F3DCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    mov currentHash, 0C55AC9C5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov currentHash, 0C85426DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    mov currentHash, 01683D82Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    mov currentHash, 041A9E191h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtomEx ENDP

NtAddBootEntry PROC
    mov currentHash, 0458B7B2Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    mov currentHash, 00F972544h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    mov currentHash, 03D891114h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    mov currentHash, 07FE55ABDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    mov currentHash, 01CB2020Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertResumeThread ENDP

NtAlertThread PROC
    mov currentHash, 0380734AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    mov currentHash, 009133583h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    mov currentHash, 049AA1A9Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    mov currentHash, 03C8415D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    mov currentHash, 0FE65D1FFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    mov currentHash, 0110A3997h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    mov currentHash, 06C973072h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    mov currentHash, 010B1033Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    mov currentHash, 061550348h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    mov currentHash, 01E8F2520h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    mov currentHash, 033AE7155h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    mov currentHash, 0E1B28661h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    mov currentHash, 04ED3ADC1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    mov currentHash, 0FE6AE8DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    mov currentHash, 042F6634Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    mov currentHash, 0FE67EBCEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    mov currentHash, 0108A121Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    mov currentHash, 038BCC8D7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    mov currentHash, 007AEFAC8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    mov currentHash, 0DA41CFE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    mov currentHash, 064F17F5Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    mov currentHash, 03ABF3930h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    mov currentHash, 0E073EFE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    mov currentHash, 0A1BEB813h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    mov currentHash, 01CBFD609h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    mov currentHash, 0349C283Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    mov currentHash, 007BAC4E2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    mov currentHash, 0D74AC2EBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    mov currentHash, 026B63B3Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    mov currentHash, 064C9605Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    mov currentHash, 0AF96D807h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    mov currentHash, 00622F45Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    mov currentHash, 01CBA4A67h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    mov currentHash, 02037B507h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    mov currentHash, 058BA8AE0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    mov currentHash, 0397931E9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    mov currentHash, 0D794D342h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    mov currentHash, 0795C1FCEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    mov currentHash, 09EC04A8Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitComplete ENDP

NtCommitEnlistment PROC
    mov currentHash, 07B258F42h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    mov currentHash, 00AE60C77h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    mov currentHash, 03AAF0A0Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitTransaction ENDP

NtCompactKeys PROC
    mov currentHash, 026471BD0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompactKeys ENDP

NtCompareObjects PROC
    mov currentHash, 049D54157h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    mov currentHash, 068C56852h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    mov currentHash, 00D94050Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    mov currentHash, 030B2196Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompleteConnectPort ENDP

NtCompressKey PROC
    mov currentHash, 0D0A8E717h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompressKey ENDP

NtConnectPort PROC
    mov currentHash, 03EB03B22h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov currentHash, 03795DD89h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    mov currentHash, 07AE3022Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    mov currentHash, 03AA4760Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    mov currentHash, 042AEB0D4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    mov currentHash, 05A1F9944h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    mov currentHash, 079DC023Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    mov currentHash, 034944A63h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    mov currentHash, 0039635D2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    mov currentHash, 09C929232h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    mov currentHash, 02D6903F3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobObject ENDP

NtCreateJobSet PROC
    mov currentHash, 0F3CEDF11h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    mov currentHash, 054BC1602h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    mov currentHash, 069329245h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    mov currentHash, 067D8535Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    mov currentHash, 02EBDB48Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    mov currentHash, 0BE119B48h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    mov currentHash, 096197812h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    mov currentHash, 074B2026Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePagingFile ENDP

NtCreatePartition PROC
    mov currentHash, 014825455h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePartition ENDP

NtCreatePort PROC
    mov currentHash, 01CB1E5DCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    mov currentHash, 04E908625h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    mov currentHash, 05FDE4E52h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateProfile PROC
    mov currentHash, 000DAF080h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfile ENDP

NtCreateProfileEx PROC
    mov currentHash, 0805BB2E1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    mov currentHash, 01E8E381Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    mov currentHash, 0103302B8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    mov currentHash, 01D0FC3B4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    mov currentHash, 09A26E8CBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    mov currentHash, 054AA9BDDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtCreateTimer PROC
    mov currentHash, 0144622FFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer ENDP

NtCreateTimer2 PROC
    mov currentHash, 0EB52365Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer2 ENDP

NtCreateToken PROC
    mov currentHash, 020482AD1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateToken ENDP

NtCreateTokenEx PROC
    mov currentHash, 08A99CC66h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    mov currentHash, 0168C3411h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    mov currentHash, 0B22E98B3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    mov currentHash, 065392CE4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    mov currentHash, 0393C3BA2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    mov currentHash, 020BD2726h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    mov currentHash, 01CBECF89h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    mov currentHash, 02AA91E26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    mov currentHash, 08E248FABh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    mov currentHash, 096119E7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugContinue ENDP

NtDeleteAtom PROC
    mov currentHash, 0D27FF1E0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    mov currentHash, 0C99D3CE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    mov currentHash, 0DF9315D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    mov currentHash, 0E278ECDCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteFile ENDP

NtDeleteKey PROC
    mov currentHash, 01FAB3208h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    mov currentHash, 01897120Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    mov currentHash, 01EB55799h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    mov currentHash, 0A79A9224h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    mov currentHash, 076BC4014h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    mov currentHash, 00CC22507h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    mov currentHash, 0F82FF685h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    mov currentHash, 01E8E2A1Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisplayString ENDP

NtDrawText PROC
    mov currentHash, 0D24BD7C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDrawText ENDP

NtEnableLastKnownGood PROC
    mov currentHash, 09DCEAD19h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    mov currentHash, 04C914109h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    mov currentHash, 034844D6Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    mov currentHash, 07FD24267h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    mov currentHash, 06AB56A29h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    mov currentHash, 038A81E21h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtExtendSection ENDP

NtFilterBootOption PROC
    mov currentHash, 03A92D781h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterBootOption ENDP

NtFilterToken PROC
    mov currentHash, 0E55CD3D8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterToken ENDP

NtFilterTokenEx PROC
    mov currentHash, 00484F1F9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    mov currentHash, 00B9845AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    mov currentHash, 0F557C2CEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    mov currentHash, 0693F9567h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstructionCache ENDP

NtFlushKey PROC
    mov currentHash, 0D461E3DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    mov currentHash, 07EBC7E2Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    mov currentHash, 0B31C89AFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    mov currentHash, 06BC0429Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    mov currentHash, 011BC2A12h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    mov currentHash, 026452CC5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    mov currentHash, 013CB00ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    mov currentHash, 0B28BB815h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    mov currentHash, 044CB0A13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    mov currentHash, 06B4E279Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    mov currentHash, 006937878h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    mov currentHash, 084EAA254h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    mov currentHash, 0B49BA434h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    mov currentHash, 084B7B211h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    mov currentHash, 01B9E1E0Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextProcess ENDP

NtGetNextThread PROC
    mov currentHash, 0EE4B2CEDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    mov currentHash, 02B12C80Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    mov currentHash, 0823CAA87h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    mov currentHash, 0105E2CDAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    mov currentHash, 04550AA4Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    mov currentHash, 0B000BAAEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    mov currentHash, 02C93C098h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    mov currentHash, 06CECA3B6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    mov currentHash, 0BC533055h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    mov currentHash, 0CB578F84h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    mov currentHash, 00440C162h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    mov currentHash, 027AA3515h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsUILanguageComitted ENDP

NtListenPort PROC
    mov currentHash, 0E173E0FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListenPort ENDP

NtLoadDriver PROC
    mov currentHash, 012B81A26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    mov currentHash, 0849AD429h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    mov currentHash, 0ECA229FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadHotPatch ENDP

NtLoadKey PROC
    mov currentHash, 0083A69A3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey ENDP

NtLoadKey2 PROC
    mov currentHash, 0AB3221EEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    mov currentHash, 07399B624h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKeyEx ENDP

NtLockFile PROC
    mov currentHash, 03A3D365Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockFile ENDP

NtLockProductActivationKeys PROC
    mov currentHash, 04F3248A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    mov currentHash, 0DEABF13Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    mov currentHash, 00794EEFBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    mov currentHash, 0A13ECFE4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    mov currentHash, 01E3D74A2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    mov currentHash, 00AE16A33h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManagePartition ENDP

NtMapCMFModule PROC
    mov currentHash, 0169B1AFCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    mov currentHash, 029B5721Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    mov currentHash, 0365CF80Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    mov currentHash, 0099AFCE1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    mov currentHash, 021C8CD98h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    mov currentHash, 0AA3A816Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    mov currentHash, 08B54FFA8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    mov currentHash, 0F1FBD3A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    mov currentHash, 065BE7236h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    mov currentHash, 001890314h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    mov currentHash, 05BD55E63h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    mov currentHash, 020944861h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    mov currentHash, 07067F071h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    mov currentHash, 0F341013Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    mov currentHash, 00F99C3DCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    mov currentHash, 0104416DEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    mov currentHash, 0889ABA21h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    mov currentHash, 0E87FEBE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    mov currentHash, 0B22DF5FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    mov currentHash, 02AAD0E7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    mov currentHash, 0108DD0DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    mov currentHash, 0785F07BDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    mov currentHash, 0E75BFBEAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    mov currentHash, 09CC47B51h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    mov currentHash, 0F9512419h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    mov currentHash, 09306CBBBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSemaphore ENDP

NtOpenSession PROC
    mov currentHash, 0D2053455h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    mov currentHash, 00A943819h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    mov currentHash, 0183F5496h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtOpenTimer PROC
    mov currentHash, 00B189804h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTimer ENDP

NtOpenTransaction PROC
    mov currentHash, 09C089C9Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    mov currentHash, 005E791C6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    mov currentHash, 0C6693A38h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    mov currentHash, 0089003FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    mov currentHash, 0F9A71DCCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    mov currentHash, 004D057EEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    mov currentHash, 0D9469E8Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    mov currentHash, 028950FC5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    mov currentHash, 0E12EDD61h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    mov currentHash, 012B41622h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    mov currentHash, 00E913E3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationComplete ENDP

NtPropagationFailed PROC
    mov currentHash, 04ED9AF84h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationFailed ENDP

NtPulseEvent PROC
    mov currentHash, 0000A1B9Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    mov currentHash, 0EAD9F64Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    mov currentHash, 0F7EEFB75h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    mov currentHash, 0178D1F1Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    mov currentHash, 074CA7E6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    mov currentHash, 0C8530A69h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    mov currentHash, 0E65ACF07h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    mov currentHash, 013461DDBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    mov currentHash, 0E4A4944Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    mov currentHash, 0C6CDC662h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    mov currentHash, 09B07BA93h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    mov currentHash, 0A80AAF91h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    mov currentHash, 02FB12E23h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    mov currentHash, 007A5C2EBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    mov currentHash, 0A73AA8A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    mov currentHash, 007B6EEEEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    mov currentHash, 002ED227Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    mov currentHash, 0B32C9DB0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    mov currentHash, 0CC9A2E03h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    mov currentHash, 04FC9365Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    mov currentHash, 0D73B26AFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    mov currentHash, 05ED55E47h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    mov currentHash, 0D4433CCCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    mov currentHash, 0825AF1A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    mov currentHash, 0DE19F380h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    mov currentHash, 00DB3606Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    mov currentHash, 061DAB182h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    mov currentHash, 069306CA8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    mov currentHash, 0E2B83781h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    mov currentHash, 07D27A48Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    mov currentHash, 013BCE0C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    mov currentHash, 005AAE1D7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    mov currentHash, 03AAA6416h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    mov currentHash, 01702E100h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    mov currentHash, 0CA9129DAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    mov currentHash, 0534A0796h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    mov currentHash, 09694C44Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    mov currentHash, 0C24DE4D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    mov currentHash, 0A3039595h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    mov currentHash, 0FAEB18E7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    mov currentHash, 0FCACFE16h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    mov currentHash, 03F6E1A3Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseException ENDP

NtRaiseHardError PROC
    mov currentHash, 0CF5CD1CDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    mov currentHash, 09236B7A4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    mov currentHash, 0C8530818h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    mov currentHash, 0605F52FCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    mov currentHash, 006379837h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    mov currentHash, 0049326C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    mov currentHash, 0EE76DE3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    mov currentHash, 0DB88FCD3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    mov currentHash, 03E9FE8BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    mov currentHash, 06496A2E8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    mov currentHash, 0CA5FCBF4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    mov currentHash, 0E9DF04ACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameKey ENDP

NtRenameTransactionManager PROC
    mov currentHash, 005B75116h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    mov currentHash, 0DD58FCC2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    mov currentHash, 0AEAF5BD5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    mov currentHash, 0E47EE1EEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    mov currentHash, 0E073F9F6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestPort ENDP

NtResetEvent PROC
    mov currentHash, 0DC313C62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetEvent ENDP

NtResetWriteWatch PROC
    mov currentHash, 012DF2E5Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetWriteWatch ENDP

NtRestoreKey PROC
    mov currentHash, 02BFE4615h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRestoreKey ENDP

NtResumeProcess PROC
    mov currentHash, 083D37ABEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    mov currentHash, 00895C8C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    mov currentHash, 054B85056h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    mov currentHash, 0D9469E8Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    mov currentHash, 010B7F7E2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    mov currentHash, 003D73B7Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    mov currentHash, 00D339D2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    mov currentHash, 077CB5654h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKey ENDP

NtSaveKeyEx PROC
    mov currentHash, 01790EBE4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    mov currentHash, 025A32A3Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    mov currentHash, 0128D0102h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    mov currentHash, 097421756h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    mov currentHash, 0B16B8BC3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    mov currentHash, 007990D1Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    mov currentHash, 022BB2406h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    mov currentHash, 02499AD4Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    mov currentHash, 0268C2825h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    mov currentHash, 0D749D8EDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    mov currentHash, 0FB72E0FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    mov currentHash, 0BC24BA98h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    mov currentHash, 0A40A192Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    mov currentHash, 0B7998D35h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    mov currentHash, 0BD2A4348h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEaFile ENDP

NtSetHighEventPair PROC
    mov currentHash, 044CC405Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    mov currentHash, 050D47445h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    mov currentHash, 0FF5D1906h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    mov currentHash, 01C21E44Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    mov currentHash, 0C054E1C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    mov currentHash, 08FA0B52Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    mov currentHash, 0D859E5FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    mov currentHash, 0E3C7FF6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    mov currentHash, 06EF76E62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    mov currentHash, 08D088394h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    mov currentHash, 0174BCAE0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    mov currentHash, 001B56948h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    mov currentHash, 019901D1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    mov currentHash, 084509CCEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    mov currentHash, 0EC263464h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    mov currentHash, 0C030E6A5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    mov currentHash, 02695F9C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    mov currentHash, 08CA4FF44h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    mov currentHash, 011923702h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    mov currentHash, 004DC004Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    mov currentHash, 09E3DA8AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    mov currentHash, 0D847888Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    mov currentHash, 01E88F888h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    mov currentHash, 01C0124BEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    mov currentHash, 0D9B6DF25h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    mov currentHash, 0D950A7D2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    mov currentHash, 03EAB4F3Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    mov currentHash, 08204E480h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    mov currentHash, 09BD89B16h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer2 ENDP

NtSetTimerEx PROC
    mov currentHash, 0B54085F8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    mov currentHash, 054C27455h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    mov currentHash, 07458C176h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    mov currentHash, 01EBFD488h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    mov currentHash, 01288F19Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    mov currentHash, 0CCEDF547h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    mov currentHash, 0C452D8B7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    mov currentHash, 0A63B9E97h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    mov currentHash, 0223C44CFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSinglePhaseReject ENDP

NtStartProfile PROC
    mov currentHash, 0815AD3EFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartProfile ENDP

NtStopProfile PROC
    mov currentHash, 0049DCAB8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    mov currentHash, 09E39D3E0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    mov currentHash, 0315E32C0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 036932821h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtSystemDebugControl PROC
    mov currentHash, 0019FF3D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    mov currentHash, 060BF7434h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    mov currentHash, 0049F5245h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateJobObject ENDP

NtTestAlert PROC
    mov currentHash, 0CF52DAF3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtThawRegistry PROC
    mov currentHash, 0C2A133E8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawRegistry ENDP

NtThawTransactions PROC
    mov currentHash, 077E74B55h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawTransactions ENDP

NtTraceControl PROC
    mov currentHash, 03FA9F9F3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceControl ENDP

NtTranslateFilePath PROC
    mov currentHash, 0FF56FCCDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    mov currentHash, 08F159CA1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    mov currentHash, 0DD6A2061h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadDriver ENDP

NtUnloadKey PROC
    mov currentHash, 068BD075Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey ENDP

NtUnloadKey2 PROC
    mov currentHash, 033D56F58h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    mov currentHash, 029E71F58h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    mov currentHash, 02A7B5CEFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    mov currentHash, 0FFA8C917h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    mov currentHash, 04A914E2Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    mov currentHash, 0EA3FB7FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    mov currentHash, 0CD02DFB3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    mov currentHash, 08B9012A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    mov currentHash, 046BA6C7Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    mov currentHash, 000CF1D66h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    mov currentHash, 090CA6AADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    mov currentHash, 0F8AED47Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    mov currentHash, 0D34FC1D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    mov currentHash, 0B4165C0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    mov currentHash, 06AD32A5Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    mov currentHash, 0F7BC10D7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    mov currentHash, 0C089E259h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    mov currentHash, 0F56929C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    mov currentHash, 0D843FA97h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    mov currentHash, 09813DAC7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    mov currentHash, 088DA86B3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    mov currentHash, 0B053F2E9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    mov currentHash, 0FE3CC196h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    mov currentHash, 000902D08h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    mov currentHash, 08525A983h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListTransactions ENDP

NtMarshallTransaction PROC
    mov currentHash, 0905B92CFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMarshallTransaction ENDP

NtPullTransaction PROC
    mov currentHash, 0900BD6DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    mov currentHash, 08E15828Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    mov currentHash, 0DC8FDA1Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    mov currentHash, 0031E49A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartTm ENDP

NtSetInformationProcess PROC
    mov currentHash, 08117868Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    mov currentHash, 0359314C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    mov currentHash, 09801A1BCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    mov currentHash, 0B9A357A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    mov currentHash, 0A0BF2EA8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManageHotPatch ENDP

NtContinueEx PROC
    mov currentHash, 05FC5BBB9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinueEx ENDP

end