.data
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

NtAccessCheck PROC
    mov currentHash, 0A8128191h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    mov currentHash, 007ADF9AFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    mov currentHash, 0C172C2FDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    mov currentHash, 041F01F39h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    mov currentHash, 01AFD7E0Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    mov currentHash, 0BE0C7F22h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallbackReturn ENDP

NtReadFile PROC
    mov currentHash, 0AA3A98AEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFile ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 0C058080Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    mov currentHash, 03E3DD038h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    mov currentHash, 04AE42A7Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    mov currentHash, 072E84BB4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    mov currentHash, 026B5213Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    mov currentHash, 0A0B2DD52h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyPort ENDP

NtSetInformationThread PROC
    mov currentHash, 0BC9874B7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationThread ENDP

NtSetEvent PROC
    mov currentHash, 032F00B54h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEvent ENDP

NtClose PROC
    mov currentHash, 002961525h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtQueryObject PROC
    mov currentHash, 03AA63205h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryObject ENDP

NtQueryInformationFile PROC
    mov currentHash, 054C4CFF0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtOpenKey PROC
    mov currentHash, 03CA05F3Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKey ENDP

NtEnumerateValueKey PROC
    mov currentHash, 0BD9CD07Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateValueKey ENDP

NtFindAtom PROC
    mov currentHash, 068FD6D68h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    mov currentHash, 0C3A2FB66h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    mov currentHash, 057E24A75h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryKey ENDP

NtQueryValueKey PROC
    mov currentHash, 067DF6042h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 0910B898Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    mov currentHash, 08D2780BEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    mov currentHash, 0108E165Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    mov currentHash, 0F864F4FEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFileGather ENDP

NtCreateKey PROC
    mov currentHash, 066F99583h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 001D1337Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    mov currentHash, 05C8F5710h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    mov currentHash, 030AC353Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    mov currentHash, 08D96F719h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    mov currentHash, 064C94B1Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    mov currentHash, 08B2387A7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    mov currentHash, 01550885Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    mov currentHash, 03317FE3Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtOpenProcess PROC
    mov currentHash, 001A7062Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtSetInformationFile PROC
    mov currentHash, 0D97CEFEFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    mov currentHash, 0F66AF6F9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    mov currentHash, 078BF4676h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 01297EC1Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    mov currentHash, 0058A6375h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    mov currentHash, 005BF0620h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    mov currentHash, 006AC7662h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    mov currentHash, 023AC3B27h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    mov currentHash, 01F0B49D5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    mov currentHash, 0190659CFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    mov currentHash, 023B5C5A1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    mov currentHash, 061DB0804h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateKey ENDP

NtOpenFile PROC
    mov currentHash, 068C06462h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenFile ENDP

NtDelayExecution PROC
    mov currentHash, 056CF9A95h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 0593BA37Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    mov currentHash, 0D436DEABh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtOpenSection PROC
    mov currentHash, 0D601D693h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtQueryTimer PROC
    mov currentHash, 0118B0128h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimer ENDP

NtFsControlFile PROC
    mov currentHash, 027BED925h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 01D931513h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    mov currentHash, 068AFF4A0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    mov currentHash, 0180666FBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    mov currentHash, 0C6D85AEEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAttributesFile ENDP

NtClearEvent PROC
    mov currentHash, 00AB72B02h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearEvent ENDP

NtReadVirtualMemory PROC
    mov currentHash, 009991EF7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    mov currentHash, 09B009C9Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 05D991144h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    mov currentHash, 075D0474Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateToken ENDP

NtContinue PROC
    mov currentHash, 0D940C5F3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    mov currentHash, 02DB33010h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    mov currentHash, 00D51D5F5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtYieldExecution PROC
    mov currentHash, 0C6C10899h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtYieldExecution ENDP

NtAddAtom PROC
    mov currentHash, 046AD334Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtom ENDP

NtCreateEvent PROC
    mov currentHash, 00EC5095Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    mov currentHash, 075348F71h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    mov currentHash, 00A96020Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtFlushBuffersFile PROC
    mov currentHash, 0F05BFEF0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    mov currentHash, 01D96E0DFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    mov currentHash, 06B933746h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcessEx ENDP

NtCreateThread PROC
    mov currentHash, 02C87B6B9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThread ENDP

NtIsProcessInJob PROC
    mov currentHash, 0AF947F26h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 011B0213Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    mov currentHash, 0CE99E44Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySection ENDP

NtResumeThread PROC
    mov currentHash, 06CCF286Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtTerminateThread PROC
    mov currentHash, 09EB25E91h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateThread ENDP

NtReadRequestData PROC
    mov currentHash, 0C519B1CDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadRequestData ENDP

NtCreateFile PROC
    mov currentHash, 08C9D8236h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateFile ENDP

NtQueryEvent PROC
    mov currentHash, 0E6432F06h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEvent ENDP

NtWriteRequestData PROC
    mov currentHash, 0C303B7D7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    mov currentHash, 02C08249Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    mov currentHash, 01EB6DA9Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 0B6548CDAh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    mov currentHash, 00CBE7E53h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationObject ENDP

NtCancelIoFile PROC
    mov currentHash, 05AFB6C26h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFile ENDP

NtTraceEvent PROC
    mov currentHash, 032AA3722h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceEvent ENDP

NtPowerInformation PROC
    mov currentHash, 03EAA19FBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPowerInformation ENDP

NtSetValueKey PROC
    mov currentHash, 00F1BEC81h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetValueKey ENDP

NtCancelTimer PROC
    mov currentHash, 01381FE9Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer ENDP

NtSetTimer PROC
    mov currentHash, 01FCB2968h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer ENDP

NtAccessCheckByType PROC
    mov currentHash, 0A62DFA16h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    mov currentHash, 0F6779AEFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    mov currentHash, 09A5E9ACCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov currentHash, 08F836581h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    mov currentHash, 0189BCE26h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    mov currentHash, 005E1375Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtomEx ENDP

NtAddBootEntry PROC
    mov currentHash, 00DA40524h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    mov currentHash, 039951532h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    mov currentHash, 0AF2E91A2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    mov currentHash, 007910501h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    mov currentHash, 02D102DB4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertResumeThread ENDP

NtAlertThread PROC
    mov currentHash, 0043F9701h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    mov currentHash, 090AB2679h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    mov currentHash, 059ABE3BCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    mov currentHash, 080BE0EA3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    mov currentHash, 00DB23C0Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    mov currentHash, 0E8493916h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    mov currentHash, 0A680EC52h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    mov currentHash, 020B11F1Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    mov currentHash, 02D8CBAB4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    mov currentHash, 066B12972h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    mov currentHash, 0CFC29B1Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    mov currentHash, 0E6B218D1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    mov currentHash, 08C249097h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    mov currentHash, 02C433EEFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    mov currentHash, 06AF74D49h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    mov currentHash, 0AF34BCBBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    mov currentHash, 0CF58EFD6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    mov currentHash, 0129E3A53h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    mov currentHash, 03CAC011Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    mov currentHash, 031AD240Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    mov currentHash, 0257F3CD1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    mov currentHash, 03EB22728h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    mov currentHash, 0BEAEA12Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    mov currentHash, 0555B2ED4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    mov currentHash, 0922ED281h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    mov currentHash, 0846AF28Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    mov currentHash, 06D4DE278h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    mov currentHash, 0ED33EAA1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    mov currentHash, 05CFF6334h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    mov currentHash, 01088161Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    mov currentHash, 0298D5456h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    mov currentHash, 011C57F58h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    mov currentHash, 0099D372Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    mov currentHash, 00691E292h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    mov currentHash, 026DCE4E6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    mov currentHash, 038B80DEAh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    mov currentHash, 089922D44h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    mov currentHash, 081BCB51Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    mov currentHash, 0609F0A52h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitComplete ENDP

NtCommitEnlistment PROC
    mov currentHash, 031B6CEF5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    mov currentHash, 012573C88h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    mov currentHash, 0DEB2E41Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitTransaction ENDP

NtCompactKeys PROC
    mov currentHash, 05FEA5A5Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompactKeys ENDP

NtCompareObjects PROC
    mov currentHash, 0F7BBCD37h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    mov currentHash, 0168D4C4Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    mov currentHash, 00159C709h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    mov currentHash, 024B3C320h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompleteConnectPort ENDP

NtCompressKey PROC
    mov currentHash, 0EB5D1729h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompressKey ENDP

NtConnectPort PROC
    mov currentHash, 066B15D1Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov currentHash, 09D94E71Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    mov currentHash, 0BD97E7B9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    mov currentHash, 0F4C6D27Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    mov currentHash, 0AAB814BEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    mov currentHash, 0CC2AA920h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    mov currentHash, 051B1703Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    mov currentHash, 0113C37ABh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    mov currentHash, 0C79CDE37h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    mov currentHash, 004AE647Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    mov currentHash, 088D466F9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobObject ENDP

NtCreateJobSet PROC
    mov currentHash, 010027AFDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    mov currentHash, 0A069EAC6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    mov currentHash, 0462C49B6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    mov currentHash, 0152F77D8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    mov currentHash, 039B8E399h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    mov currentHash, 046C8495Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    mov currentHash, 03FA7A693h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    mov currentHash, 028E9762Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePagingFile ENDP

NtCreatePartition PROC
    mov currentHash, 06D4A31E9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePartition ENDP

NtCreatePort PROC
    mov currentHash, 0E073FFF0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    mov currentHash, 04C6C125Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    mov currentHash, 06DB70A24h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateProfile PROC
    mov currentHash, 010B1EAE0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfile ENDP

NtCreateProfileEx PROC
    mov currentHash, 06A51BC0Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    mov currentHash, 09F17DBC6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    mov currentHash, 0E6BFA26Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    mov currentHash, 0BF2F87B3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    mov currentHash, 002BECEC1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    mov currentHash, 03C3F60EAh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtCreateTimer PROC
    mov currentHash, 019937350h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer ENDP

NtCreateTimer2 PROC
    mov currentHash, 0498AB203h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer2 ENDP

NtCreateToken PROC
    mov currentHash, 03D853366h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateToken ENDP

NtCreateTokenEx PROC
    mov currentHash, 006E2B2DEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    mov currentHash, 052C9505Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    mov currentHash, 006067284h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    mov currentHash, 08C1297FBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    mov currentHash, 0351B1980h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    mov currentHash, 020B6011Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    mov currentHash, 0F6D07EF2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    mov currentHash, 04096520Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    mov currentHash, 00D9F223Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    mov currentHash, 022A8C1E4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugContinue ENDP

NtDeleteAtom PROC
    mov currentHash, 0F25ED7CEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    mov currentHash, 00D84F7F6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    mov currentHash, 041105F96h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    mov currentHash, 0C265C2C2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteFile ENDP

NtDeleteKey PROC
    mov currentHash, 037E36638h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    mov currentHash, 058DF5E4Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    mov currentHash, 029B9D324h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    mov currentHash, 016423FF2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    mov currentHash, 0278FB8B6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    mov currentHash, 0CF95B474h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    mov currentHash, 07BAE7100h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    mov currentHash, 0869AE88Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisplayString ENDP

NtDrawText PROC
    mov currentHash, 012CA5D18h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDrawText ENDP

NtEnableLastKnownGood PROC
    mov currentHash, 027B6ACA0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    mov currentHash, 02893A18Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    mov currentHash, 01B5A14C1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    mov currentHash, 0D2638E87h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    mov currentHash, 026BA3427h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    mov currentHash, 0C673E4E7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtExtendSection ENDP

NtFilterBootOption PROC
    mov currentHash, 004AE003Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterBootOption ENDP

NtFilterToken PROC
    mov currentHash, 025A13B2Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterToken ENDP

NtFilterTokenEx PROC
    mov currentHash, 09E88E876h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    mov currentHash, 008ABCBD0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    mov currentHash, 00D9F3BC2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    mov currentHash, 0B3A745B9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstructionCache ENDP

NtFlushKey PROC
    mov currentHash, 0AC998D31h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    mov currentHash, 0389B184Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    mov currentHash, 00193E7FDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    mov currentHash, 0CD983AFCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    mov currentHash, 007BF7C30h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    mov currentHash, 0C4D541D8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    mov currentHash, 03F9A055Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    mov currentHash, 0109C5840h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    mov currentHash, 0000E0493h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    mov currentHash, 014906E29h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    mov currentHash, 086B0AA12h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    mov currentHash, 0ACA3F47Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    mov currentHash, 035BC6571h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    mov currentHash, 0DC4FD6D5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    mov currentHash, 021955078h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextProcess ENDP

NtGetNextThread PROC
    mov currentHash, 0544840F7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    mov currentHash, 03A5027DEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    mov currentHash, 0299F4566h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    mov currentHash, 0E6E918FEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    mov currentHash, 0BC8A8828h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    mov currentHash, 014AF5C03h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    mov currentHash, 06AAB6A46h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    mov currentHash, 0ED57A68Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    mov currentHash, 040D93A25h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    mov currentHash, 0C05FA28Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    mov currentHash, 032BED13Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    mov currentHash, 03BD67B73h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsUILanguageComitted ENDP

NtListenPort PROC
    mov currentHash, 020B2A9B0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListenPort ENDP

NtLoadDriver PROC
    mov currentHash, 012985840h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    mov currentHash, 0E28BD026h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    mov currentHash, 0E45FDEFAh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadHotPatch ENDP

NtLoadKey PROC
    mov currentHash, 06CDB5169h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey ENDP

NtLoadKey2 PROC
    mov currentHash, 005B7FC30h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    mov currentHash, 035B3F18Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKeyEx ENDP

NtLockFile PROC
    mov currentHash, 058C7AA9Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockFile ENDP

NtLockProductActivationKeys PROC
    mov currentHash, 046DEACC1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    mov currentHash, 05987643Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    mov currentHash, 01F890917h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    mov currentHash, 008A65459h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    mov currentHash, 0E538EFA6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    mov currentHash, 0220D60D1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManagePartition ENDP

NtMapCMFModule PROC
    mov currentHash, 032AC241Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    mov currentHash, 0019D2A06h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    mov currentHash, 080934EC4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    mov currentHash, 00995150Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    mov currentHash, 08612B2AFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    mov currentHash, 0F0DABA7Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    mov currentHash, 05CA71E7Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    mov currentHash, 017D37C02h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    mov currentHash, 051BF4C3Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    mov currentHash, 02188C39Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    mov currentHash, 0A9369695h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    mov currentHash, 0931DB584h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    mov currentHash, 0055803F1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    mov currentHash, 0BE21868Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    mov currentHash, 0559AA1E6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    mov currentHash, 0F05D868Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    mov currentHash, 0E0D1B009h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    mov currentHash, 0C002D066h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    mov currentHash, 0328FAB8Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    mov currentHash, 0EDACD1E5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    mov currentHash, 0D64DB65Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    mov currentHash, 0349C3B37h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    mov currentHash, 017AA8CA3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    mov currentHash, 00A920C07h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    mov currentHash, 0704F5914h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    mov currentHash, 0168A380Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSemaphore ENDP

NtOpenSession PROC
    mov currentHash, 099017F48h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    mov currentHash, 0869E71F2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    mov currentHash, 0AA8DA427h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtOpenTimer PROC
    mov currentHash, 0098D7702h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTimer ENDP

NtOpenTransaction PROC
    mov currentHash, 0C40FE4DDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    mov currentHash, 0863E5E75h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    mov currentHash, 00393678Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    mov currentHash, 00AA6438Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    mov currentHash, 00892FCF5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    mov currentHash, 07CC81FC6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    mov currentHash, 0291A50EFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    mov currentHash, 074D82B11h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    mov currentHash, 014BA102Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    mov currentHash, 0F6BB132Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    mov currentHash, 05ABAA5E0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationComplete ENDP

NtPropagationFailed PROC
    mov currentHash, 0064126DCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationFailed ENDP

NtPulseEvent PROC
    mov currentHash, 002092BACh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    mov currentHash, 01EB2C316h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    mov currentHash, 008B30228h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    mov currentHash, 03BAD3921h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    mov currentHash, 0EF00D191h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    mov currentHash, 064472E85h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    mov currentHash, 0F846CAC9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    mov currentHash, 0DC41CAD8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    mov currentHash, 0BE91F6B2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    mov currentHash, 05AC43A4Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    mov currentHash, 04CD34942h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    mov currentHash, 0FB3DE888h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    mov currentHash, 00FB33404h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    mov currentHash, 00D14F366h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    mov currentHash, 0A53EAABDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    mov currentHash, 05F9F7302h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    mov currentHash, 074EE5277h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    mov currentHash, 01C2716BCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    mov currentHash, 006960802h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    mov currentHash, 0F7D4A874h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    mov currentHash, 00B5FD1EEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    mov currentHash, 0756D15BFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    mov currentHash, 032D30D4Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    mov currentHash, 06C533989h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    mov currentHash, 0249814DCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    mov currentHash, 03B87141Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    mov currentHash, 0D59AEA3Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    mov currentHash, 0C759DEF0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    mov currentHash, 0289BC688h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    mov currentHash, 03D85232Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    mov currentHash, 0802AF0E1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    mov currentHash, 0EA5EC38Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    mov currentHash, 016952E40h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    mov currentHash, 0183666FBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    mov currentHash, 01414871Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    mov currentHash, 013084FDCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    mov currentHash, 01E9DC9C2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    mov currentHash, 0F0DBB1F4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    mov currentHash, 063CCB579h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    mov currentHash, 060C84659h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    mov currentHash, 07EA4BAD9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    mov currentHash, 074E47C75h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseException ENDP

NtRaiseHardError PROC
    mov currentHash, 001AE1B3Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    mov currentHash, 00FEA0079h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    mov currentHash, 089C08E53h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    mov currentHash, 0B5A2E366h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    mov currentHash, 0B6A39231h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    mov currentHash, 01FB51F26h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    mov currentHash, 066B66F22h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    mov currentHash, 0515A3ABCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    mov currentHash, 090A445FEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    mov currentHash, 06C9F106Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    mov currentHash, 04A287B62h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    mov currentHash, 08D1DEAF0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameKey ENDP

NtRenameTransactionManager PROC
    mov currentHash, 09D8340A3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    mov currentHash, 0E552E4C8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    mov currentHash, 022B32E30h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    mov currentHash, 06141AF1Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    mov currentHash, 022B63F18h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestPort ENDP

NtResetEvent PROC
    mov currentHash, 00EA4E836h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetEvent ENDP

NtResetWriteWatch PROC
    mov currentHash, 022F36A52h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetWriteWatch ENDP

NtRestoreKey PROC
    mov currentHash, 035DF0868h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRestoreKey ENDP

NtResumeProcess PROC
    mov currentHash, 0B5A75637h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    mov currentHash, 0DE54DEFBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    mov currentHash, 0BE2A59A8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    mov currentHash, 073A23469h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    mov currentHash, 0228BFC3Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    mov currentHash, 00048C61Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    mov currentHash, 0B196A115h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    mov currentHash, 0DB98F832h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKey ENDP

NtSaveKeyEx PROC
    mov currentHash, 059AC6914h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    mov currentHash, 027C31C6Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    mov currentHash, 0228D4162h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    mov currentHash, 0DC4DC2C7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    mov currentHash, 0150A820Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    mov currentHash, 00F99051Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    mov currentHash, 0909DD840h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    mov currentHash, 0D00D7858h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    mov currentHash, 0D4EFCE49h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    mov currentHash, 0E14CCFC5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    mov currentHash, 07CC86D26h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    mov currentHash, 004A6541Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    mov currentHash, 024B2D833h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    mov currentHash, 00D96070Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    mov currentHash, 022B85E5Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEaFile ENDP

NtSetHighEventPair PROC
    mov currentHash, 09413988Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    mov currentHash, 0D053FCCDh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    mov currentHash, 0195A04D9h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    mov currentHash, 0388609CBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    mov currentHash, 079452B63h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    mov currentHash, 01EB0082Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    mov currentHash, 0A52582B8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    mov currentHash, 06BD2B572h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    mov currentHash, 0EE599C9Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    mov currentHash, 03388614Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    mov currentHash, 09E08C0C5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    mov currentHash, 009B15690h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    mov currentHash, 00B901DFFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    mov currentHash, 08F4297E5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    mov currentHash, 078224EBEh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    mov currentHash, 076E9163Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    mov currentHash, 060D32C06h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    mov currentHash, 02494CFE8h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    mov currentHash, 0E2B11A3Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    mov currentHash, 028D05C31h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    mov currentHash, 0091AF90Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    mov currentHash, 008A40039h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    mov currentHash, 095051921h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    mov currentHash, 01C24A919h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    mov currentHash, 0DC47DED7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    mov currentHash, 066B64076h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    mov currentHash, 0F52FEE9Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    mov currentHash, 01813892Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    mov currentHash, 077D53045h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer2 ENDP

NtSetTimerEx PROC
    mov currentHash, 0369D4C5Eh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    mov currentHash, 09E01BE8Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    mov currentHash, 08D3C8D80h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    mov currentHash, 039A2C7F3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    mov currentHash, 063A27A4Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    mov currentHash, 0869AD120h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    mov currentHash, 0120F34A2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    mov currentHash, 03B58CD3Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    mov currentHash, 01C36F24Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSinglePhaseReject ENDP

NtStartProfile PROC
    mov currentHash, 0D01A01A0h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartProfile ENDP

NtStopProfile PROC
    mov currentHash, 000BAD080h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    mov currentHash, 060CD5D50h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    mov currentHash, 0219B2214h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 0309C0235h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtSystemDebugControl PROC
    mov currentHash, 02D822D29h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    mov currentHash, 012D2EF80h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    mov currentHash, 008A7C7EBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateJobObject ENDP

NtTestAlert PROC
    mov currentHash, 0D45FFB84h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtThawRegistry PROC
    mov currentHash, 03AA92035h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawRegistry ENDP

NtThawTransactions PROC
    mov currentHash, 0E5370D6Dh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawTransactions ENDP

NtTraceControl PROC
    mov currentHash, 057CC775Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceControl ENDP

NtTranslateFilePath PROC
    mov currentHash, 072D04892h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    mov currentHash, 025BFFA8Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    mov currentHash, 0169C2ED6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadDriver ENDP

NtUnloadKey PROC
    mov currentHash, 078AF91CFh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey ENDP

NtUnloadKey2 PROC
    mov currentHash, 0B7D6EDBAh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    mov currentHash, 0CB609FBCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    mov currentHash, 0D6272648h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    mov currentHash, 007910D03h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    mov currentHash, 06288A0F2h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    mov currentHash, 0E35E2DF7h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    mov currentHash, 066CDF8F4h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    mov currentHash, 00F8C370Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    mov currentHash, 00A95B982h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    mov currentHash, 06EAA4D1Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    mov currentHash, 0208D635Ah    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    mov currentHash, 0F8A2D474h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    mov currentHash, 0A432D8B3h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    mov currentHash, 09633F6E5h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    mov currentHash, 0D64CECC6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    mov currentHash, 0CA110345h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    mov currentHash, 0463560A1h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    mov currentHash, 05B403FCBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    mov currentHash, 01E803815h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    mov currentHash, 008A20831h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    mov currentHash, 0B4B823BBh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    mov currentHash, 0809AD644h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    mov currentHash, 008AA2B3Ch    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    mov currentHash, 0D88A02DCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    mov currentHash, 0198C4B2Bh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListTransactions ENDP

NtMarshallTransaction PROC
    mov currentHash, 0108A3217h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMarshallTransaction ENDP

NtPullTransaction PROC
    mov currentHash, 0148D3017h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    mov currentHash, 03EA35238h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    mov currentHash, 03CB53824h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    mov currentHash, 0F05C1727h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartTm ENDP

NtSetInformationProcess PROC
    mov currentHash, 001AB0A34h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    mov currentHash, 00C6322BCh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    mov currentHash, 098AB068Fh    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    mov currentHash, 0972EA4B6h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    mov currentHash, 09CA15581h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManageHotPatch ENDP

NtContinueEx PROC
    mov currentHash, 01CB3A186h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinueEx ENDP

RtlCreateUserThread PROC
    mov currentHash, 094BFDA95h    ; Load function hash into ECX.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
RtlCreateUserThread ENDP

end