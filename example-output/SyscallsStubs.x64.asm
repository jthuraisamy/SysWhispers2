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
    mov currentHash, 0FA40F4F9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    mov currentHash, 011A63B35h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    mov currentHash, 064F17B62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    mov currentHash, 0238A0D17h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    mov currentHash, 0009E3E33h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    mov currentHash, 0168C371Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallbackReturn ENDP

NtReadFile PROC
    mov currentHash, 0C544CDF1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFile ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 022342AD2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    mov currentHash, 0E97AEB1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    mov currentHash, 0088E0821h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    mov currentHash, 034A10CFCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    mov currentHash, 0ACFE8EA0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    mov currentHash, 062B0692Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyPort ENDP

NtSetInformationThread PROC
    mov currentHash, 00A2E4E86h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationThread ENDP

NtSetEvent PROC
    mov currentHash, 058924AF4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEvent ENDP

NtClose PROC
    mov currentHash, 00352369Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtQueryObject PROC
    mov currentHash, 08CA077CCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryObject ENDP

NtQueryInformationFile PROC
    mov currentHash, 0A635B086h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtOpenKey PROC
    mov currentHash, 00F1A54C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKey ENDP

NtEnumerateValueKey PROC
    mov currentHash, 016AB2319h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateValueKey ENDP

NtFindAtom PROC
    mov currentHash, 03565D433h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    mov currentHash, 0025D728Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    mov currentHash, 008172BACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryKey ENDP

NtQueryValueKey PROC
    mov currentHash, 0E15C142Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 01F88E9E7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    mov currentHash, 0D99B2213h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    mov currentHash, 08E9DAF4Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    mov currentHash, 02B907B53h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteFileGather ENDP

NtCreateKey PROC
    mov currentHash, 07EC9073Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 0099E0519h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    mov currentHash, 060F36F68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    mov currentHash, 02D4A0AD0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    mov currentHash, 035AA1F32h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    mov currentHash, 0E273D9DCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    mov currentHash, 09514A39Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    mov currentHash, 0F8512DEAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    mov currentHash, 024881E11h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtOpenProcess PROC
    mov currentHash, 006AC0521h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtSetInformationFile PROC
    mov currentHash, 0CA7AC2ECh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    mov currentHash, 004960E0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    mov currentHash, 00F2EC371h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 0568C3591h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    mov currentHash, 0A25FEA98h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    mov currentHash, 0FE26D5BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    mov currentHash, 030863C0Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    mov currentHash, 0159C1D07h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    mov currentHash, 02FBAF2EFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    mov currentHash, 0791FB957h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    mov currentHash, 037D24B39h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    mov currentHash, 0B6AE97F4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateKey ENDP

NtOpenFile PROC
    mov currentHash, 0AD1C2B01h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenFile ENDP

NtDelayExecution PROC
    mov currentHash, 0520D529Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 058BBAAE2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    mov currentHash, 054CD765Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtOpenSection PROC
    mov currentHash, 00A9E284Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtQueryTimer PROC
    mov currentHash, 0179F7F46h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimer ENDP

NtFsControlFile PROC
    mov currentHash, 06AF45662h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 005953B23h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    mov currentHash, 05CDA584Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    mov currentHash, 03EA1F6FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    mov currentHash, 0DD5DD9FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAttributesFile ENDP

NtClearEvent PROC
    mov currentHash, 0200B65DAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearEvent ENDP

NtReadVirtualMemory PROC
    mov currentHash, 0071473E9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    mov currentHash, 030D52978h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 001940B2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    mov currentHash, 06DD92558h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDuplicateToken ENDP

NtContinue PROC
    mov currentHash, 0009CD3D0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    mov currentHash, 013C5D178h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    mov currentHash, 02E8A0C2Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtYieldExecution PROC
    mov currentHash, 014B63E33h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtYieldExecution ENDP

NtAddAtom PROC
    mov currentHash, 022BF272Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtom ENDP

NtCreateEvent PROC
    mov currentHash, 0B0B4AF3Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    mov currentHash, 0E5B3BD76h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    mov currentHash, 04EC54C51h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtFlushBuffersFile PROC
    mov currentHash, 06CFB5E2Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    mov currentHash, 0FD6DDFBBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    mov currentHash, 0B998FB42h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcessEx ENDP

NtCreateThread PROC
    mov currentHash, 0AF8CB334h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThread ENDP

NtIsProcessInJob PROC
    mov currentHash, 05CE54854h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 00F940311h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    mov currentHash, 002EC25B9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySection ENDP

NtResumeThread PROC
    mov currentHash, 07D5445CFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtTerminateThread PROC
    mov currentHash, 0228E3037h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateThread ENDP

NtReadRequestData PROC
    mov currentHash, 0A23EB14Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadRequestData ENDP

NtCreateFile PROC
    mov currentHash, 02A9AE32Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateFile ENDP

NtQueryEvent PROC
    mov currentHash, 02AB1F0E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEvent ENDP

NtWriteRequestData PROC
    mov currentHash, 09DC08975h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    mov currentHash, 03C802E0Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    mov currentHash, 0DD42B9D5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 061AD6331h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    mov currentHash, 0271915A7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationObject ENDP

NtCancelIoFile PROC
    mov currentHash, 0821B7543h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFile ENDP

NtTraceEvent PROC
    mov currentHash, 0CAED7BD0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceEvent ENDP

NtPowerInformation PROC
    mov currentHash, 054C25A5Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPowerInformation ENDP

NtSetValueKey PROC
    mov currentHash, 01DC11E58h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetValueKey ENDP

NtCancelTimer PROC
    mov currentHash, 001A23302h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer ENDP

NtSetTimer PROC
    mov currentHash, 005977F7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer ENDP

NtAccessCheckByType PROC
    mov currentHash, 0D442E30Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    mov currentHash, 07EA17221h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    mov currentHash, 0552A6982h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    mov currentHash, 099B41796h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    mov currentHash, 01A8958A0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    mov currentHash, 09390C74Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddAtomEx ENDP

NtAddBootEntry PROC
    mov currentHash, 005951912h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    mov currentHash, 03B67B174h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    mov currentHash, 025971314h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    mov currentHash, 007900309h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    mov currentHash, 0A48BA81Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertResumeThread ENDP

NtAlertThread PROC
    mov currentHash, 01CA4540Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    mov currentHash, 0B8A26896h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    mov currentHash, 0FFE51B65h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    mov currentHash, 018B4E6C9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    mov currentHash, 019BF3A24h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    mov currentHash, 0338FFDD3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    mov currentHash, 0C8503B3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    mov currentHash, 030B2213Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    mov currentHash, 073D77E7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    mov currentHash, 03EB1DDDEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    mov currentHash, 0636DBF29h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    mov currentHash, 0194B9F58h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    mov currentHash, 0C4F5DE41h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    mov currentHash, 0389F4A77h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    mov currentHash, 02CA81D13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    mov currentHash, 0FA1DE794h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    mov currentHash, 00C982C0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    mov currentHash, 01888F4C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    mov currentHash, 056EC6753h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    mov currentHash, 008B3EDDAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    mov currentHash, 022B5D93Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    mov currentHash, 02233A722h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    mov currentHash, 0D836C9DAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    mov currentHash, 0C654C5C9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    mov currentHash, 0F85F36EDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    mov currentHash, 0024618CEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    mov currentHash, 0A40091ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    mov currentHash, 040998DC8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    mov currentHash, 022B2A5B8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    mov currentHash, 0C897E64Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    mov currentHash, 0D65AEDFDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    mov currentHash, 0FF2A6100h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    mov currentHash, 007B22910h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    mov currentHash, 08736BB65h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    mov currentHash, 0F758392Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    mov currentHash, 0256033EAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    mov currentHash, 003A35E2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    mov currentHash, 0BC9C9AC6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    mov currentHash, 00C9007FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitComplete ENDP

NtCommitEnlistment PROC
    mov currentHash, 0164B0FC6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    mov currentHash, 004B43E31h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    mov currentHash, 018813A51h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCommitTransaction ENDP

NtCompactKeys PROC
    mov currentHash, 057BA6A14h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompactKeys ENDP

NtCompareObjects PROC
    mov currentHash, 084648AF6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    mov currentHash, 0AEF09E73h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    mov currentHash, 0F494EC01h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    mov currentHash, 03A7637F8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompleteConnectPort ENDP

NtCompressKey PROC
    mov currentHash, 0782E5F8Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCompressKey ENDP

NtConnectPort PROC
    mov currentHash, 0A23C9072h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    mov currentHash, 079468945h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    mov currentHash, 0009E21C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    mov currentHash, 0FAD436BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    mov currentHash, 0426E10B4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    mov currentHash, 0CA2FDE86h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    mov currentHash, 00F90ECC7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    mov currentHash, 012B1CCFCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    mov currentHash, 0178C3F36h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    mov currentHash, 00E1750D7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    mov currentHash, 0F65B6E57h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobObject ENDP

NtCreateJobSet PROC
    mov currentHash, 08740AF1Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    mov currentHash, 0A69A66C6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    mov currentHash, 068CF755Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    mov currentHash, 017C73D1Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    mov currentHash, 0E47DC2FEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    mov currentHash, 0FDDC08A5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    mov currentHash, 0ED7AA75Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    mov currentHash, 054C36C00h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePagingFile ENDP

NtCreatePartition PROC
    mov currentHash, 0444E255Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePartition ENDP

NtCreatePort PROC
    mov currentHash, 02EB4CCDAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    mov currentHash, 009B1CFEBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    mov currentHash, 081288EB0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateProfile PROC
    mov currentHash, 06E3E6AA4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfile ENDP

NtCreateProfileEx PROC
    mov currentHash, 0029AC0C1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    mov currentHash, 0970FD3DEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    mov currentHash, 06E52FA4Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    mov currentHash, 0FCB62D1Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    mov currentHash, 083189384h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    mov currentHash, 096A7CC64h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtCreateTimer PROC
    mov currentHash, 0E58D8F55h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer ENDP

NtCreateTimer2 PROC
    mov currentHash, 0B0684CA6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTimer2 ENDP

NtCreateToken PROC
    mov currentHash, 0099F9FBFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateToken ENDP

NtCreateTokenEx PROC
    mov currentHash, 06022A67Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    mov currentHash, 03CEE2243h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    mov currentHash, 01BA730FAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    mov currentHash, 0EC26CFBBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    mov currentHash, 001813F0Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    mov currentHash, 0A97288DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    mov currentHash, 0CED0FB42h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    mov currentHash, 0089C140Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    mov currentHash, 0923099ADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    mov currentHash, 05D24BC68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDebugContinue ENDP

NtDeleteAtom PROC
    mov currentHash, 0BED35C8Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    mov currentHash, 0336B3BE4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    mov currentHash, 033930B14h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    mov currentHash, 06EF46592h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteFile ENDP

NtDeleteKey PROC
    mov currentHash, 03AEE1D71h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    mov currentHash, 016B57464h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    mov currentHash, 02A88393Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    mov currentHash, 036820931h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    mov currentHash, 032CE441Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    mov currentHash, 0A8B02387h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    mov currentHash, 0386B35C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    mov currentHash, 076E83238h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDisplayString ENDP

NtDrawText PROC
    mov currentHash, 04918735Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDrawText ENDP

NtEnableLastKnownGood PROC
    mov currentHash, 02DBE03F4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    mov currentHash, 02C97BD9Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    mov currentHash, 07CDC2D7Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    mov currentHash, 053AF8FFBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    mov currentHash, 096B4A608h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    mov currentHash, 00E8A340Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtExtendSection ENDP

NtFilterBootOption PROC
    mov currentHash, 008A20BCFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterBootOption ENDP

NtFilterToken PROC
    mov currentHash, 07FD56972h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterToken ENDP

NtFilterTokenEx PROC
    mov currentHash, 08E59B5DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    mov currentHash, 026D4E08Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    mov currentHash, 0A5BAD1A1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    mov currentHash, 00DAE4997h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushInstructionCache ENDP

NtFlushKey PROC
    mov currentHash, 09ED4BF6Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    mov currentHash, 0D83A3DA2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    mov currentHash, 08713938Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    mov currentHash, 0A538B5A7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    mov currentHash, 0E5BEEE26h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    mov currentHash, 0069B203Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    mov currentHash, 04FAA257Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    mov currentHash, 076BCA01Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    mov currentHash, 0148F1A13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    mov currentHash, 00C9C1E2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    mov currentHash, 08E33C8E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    mov currentHash, 05AD599AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    mov currentHash, 0A43BB4B4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    mov currentHash, 07ACEA663h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    mov currentHash, 00DA3362Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextProcess ENDP

NtGetNextThread PROC
    mov currentHash, 09A3DD48Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    mov currentHash, 0FF5DD282h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    mov currentHash, 0EFB2719Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    mov currentHash, 08AA31383h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    mov currentHash, 03F8F0F22h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    mov currentHash, 0FA202799h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    mov currentHash, 02C9310D2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    mov currentHash, 0744F05ACh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    mov currentHash, 034901C3Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    mov currentHash, 0C690DF3Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    mov currentHash, 0A4A02186h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    mov currentHash, 0D5EB91C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtIsUILanguageComitted ENDP

NtListenPort PROC
    mov currentHash, 0DCB0DF3Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListenPort ENDP

NtLoadDriver PROC
    mov currentHash, 01C9F4E5Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    mov currentHash, 0074E907Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    mov currentHash, 09F721D4Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadHotPatch ENDP

NtLoadKey PROC
    mov currentHash, 03F1844E5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey ENDP

NtLoadKey2 PROC
    mov currentHash, 0DA270AA1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    mov currentHash, 0BBFD8746h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLoadKeyEx ENDP

NtLockFile PROC
    mov currentHash, 0E17FCDAFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockFile ENDP

NtLockProductActivationKeys PROC
    mov currentHash, 067E66A7Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    mov currentHash, 0130628B6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    mov currentHash, 00B981D77h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    mov currentHash, 0243B2EA5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    mov currentHash, 0263B5ED7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    mov currentHash, 008B1E6EDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManagePartition ENDP

NtMapCMFModule PROC
    mov currentHash, 03917A320h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    mov currentHash, 01142E82Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    mov currentHash, 0BE9CE842h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    mov currentHash, 009941D38h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    mov currentHash, 071E16D64h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    mov currentHash, 01999E00Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    mov currentHash, 06B97BFCBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    mov currentHash, 0CB12AAE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    mov currentHash, 07F837404h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    mov currentHash, 0E78FE71Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    mov currentHash, 0BABADD51h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    mov currentHash, 090B047E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    mov currentHash, 00C656AADh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    mov currentHash, 0429C0E63h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    mov currentHash, 06BDD9BA6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    mov currentHash, 010CD1A62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    mov currentHash, 086AEC878h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    mov currentHash, 050CB5D4Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    mov currentHash, 01693FCC5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    mov currentHash, 074B25FF4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    mov currentHash, 00ABA2FF1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    mov currentHash, 0B09231BFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    mov currentHash, 0079A848Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    mov currentHash, 09A319AAFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    mov currentHash, 0B66CDF77h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    mov currentHash, 0F6A700EFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSemaphore ENDP

NtOpenSession PROC
    mov currentHash, 00D814956h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    mov currentHash, 01904FB1Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    mov currentHash, 01A394106h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtOpenTimer PROC
    mov currentHash, 0EFDDD16Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTimer ENDP

NtOpenTransaction PROC
    mov currentHash, 005512406h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    mov currentHash, 075CB4D46h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    mov currentHash, 03DAA0509h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    mov currentHash, 02CB80836h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    mov currentHash, 0CBA5EC3Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    mov currentHash, 036B3A4BCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    mov currentHash, 009A70C2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    mov currentHash, 0369A4D17h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    mov currentHash, 0E121E24Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    mov currentHash, 018BE3C28h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    mov currentHash, 0EC50B8DEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationComplete ENDP

NtPropagationFailed PROC
    mov currentHash, 03B967B3Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPropagationFailed ENDP

NtPulseEvent PROC
    mov currentHash, 0B83B91A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    mov currentHash, 02A98F7CCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    mov currentHash, 01F8FFB1Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    mov currentHash, 03FA93D3Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    mov currentHash, 032B3381Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    mov currentHash, 06A583A81h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    mov currentHash, 01E2038BDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    mov currentHash, 0030611A3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    mov currentHash, 068B37000h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    mov currentHash, 05AC5645Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    mov currentHash, 09602B592h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    mov currentHash, 0E70F1F6Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    mov currentHash, 0264639ECh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    mov currentHash, 0C4592CC5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    mov currentHash, 0920FB59Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    mov currentHash, 00FB2919Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    mov currentHash, 00C982C0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    mov currentHash, 0C7A72CDFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    mov currentHash, 002921C16h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    mov currentHash, 017B127EAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    mov currentHash, 0AC3DA4AEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    mov currentHash, 0D44FD6DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    mov currentHash, 02C911B3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    mov currentHash, 0AD19D0EAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    mov currentHash, 096B0913Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    mov currentHash, 04BB626A8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    mov currentHash, 0E319B7C5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    mov currentHash, 05F927806h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    mov currentHash, 077C5FEE7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    mov currentHash, 07BDE4D76h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    mov currentHash, 090BFA0F3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    mov currentHash, 0924491DFh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    mov currentHash, 0FD6197B7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    mov currentHash, 095B8ABF2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    mov currentHash, 0EEBB8F76h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    mov currentHash, 0F7CCB537h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    mov currentHash, 0AC916FCBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    mov currentHash, 00E952C59h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    mov currentHash, 0BE05928Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    mov currentHash, 084D362C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    mov currentHash, 0A0A0EE66h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    mov currentHash, 006D2298Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseException ENDP

NtRaiseHardError PROC
    mov currentHash, 003911D39h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    mov currentHash, 049C28E91h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    mov currentHash, 09B359EA3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    mov currentHash, 06E35F61Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    mov currentHash, 0042EDC04h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    mov currentHash, 0163F1CABh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    mov currentHash, 0A23783AAh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    mov currentHash, 070C34B44h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    mov currentHash, 0A4902D8Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    mov currentHash, 09CAECE74h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    mov currentHash, 022BCCF36h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    mov currentHash, 0299D0C3Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameKey ENDP

NtRenameTransactionManager PROC
    mov currentHash, 08E319293h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    mov currentHash, 0491C78A6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    mov currentHash, 060B16C32h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    mov currentHash, 020B10F6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    mov currentHash, 05AB65B38h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestPort ENDP

NtResetEvent PROC
    mov currentHash, 0EB51ECC2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetEvent ENDP

NtResetWriteWatch PROC
    mov currentHash, 098D39446h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResetWriteWatch ENDP

NtRestoreKey PROC
    mov currentHash, 01BC3F6A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRestoreKey ENDP

NtResumeProcess PROC
    mov currentHash, 0419F7230h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    mov currentHash, 034A21431h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    mov currentHash, 068B8741Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    mov currentHash, 09136B2A1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    mov currentHash, 070BB5E67h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    mov currentHash, 01CF8004Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    mov currentHash, 011C3410Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    mov currentHash, 080016B6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKey ENDP

NtSaveKeyEx PROC
    mov currentHash, 0EB6BDED6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    mov currentHash, 0D3B4D6C4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    mov currentHash, 072ED4142h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    mov currentHash, 0B0207C61h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    mov currentHash, 0CDEFFD41h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    mov currentHash, 09F099D9Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    mov currentHash, 0CF7DE7A1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    mov currentHash, 06EB2EC62h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    mov currentHash, 04CFC0A5Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    mov currentHash, 0348E382Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    mov currentHash, 0B8AAB528h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    mov currentHash, 085A95D9Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    mov currentHash, 0AD325030h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    mov currentHash, 00F9C1D01h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    mov currentHash, 0533D3DE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetEaFile ENDP

NtSetHighEventPair PROC
    mov currentHash, 0A6AF463Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    mov currentHash, 0A6B5AA27h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    mov currentHash, 0CD9D38FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    mov currentHash, 018382487h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    mov currentHash, 00B6410F3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    mov currentHash, 01A25FA79h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    mov currentHash, 0F2C103B9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    mov currentHash, 031965B0Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    mov currentHash, 0FAA72212h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    mov currentHash, 00386750Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    mov currentHash, 028823A2Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    mov currentHash, 0AB96218Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    mov currentHash, 01B911D1Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    mov currentHash, 08A2290B6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    mov currentHash, 02581DD85h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    mov currentHash, 002980237h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    mov currentHash, 08CAEC268h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    mov currentHash, 0FB53ECFBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    mov currentHash, 016B1CAE3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    mov currentHash, 0F2D21640h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    mov currentHash, 09706A793h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    mov currentHash, 016B85055h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    mov currentHash, 0C457E39Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    mov currentHash, 037CBF2B6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    mov currentHash, 0036F07FDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    mov currentHash, 06C8F86C2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    mov currentHash, 08725CE82h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    mov currentHash, 0923D7C34h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    mov currentHash, 079929A43h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimer2 ENDP

NtSetTimerEx PROC
    mov currentHash, 072E8ACBEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    mov currentHash, 041146399h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    mov currentHash, 0D14ED7D4h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    mov currentHash, 024B1D2A2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    mov currentHash, 0999D8030h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    mov currentHash, 0D36EC9C1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    mov currentHash, 0151D1594h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    mov currentHash, 00AB43429h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    mov currentHash, 0745E2285h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSinglePhaseReject ENDP

NtStartProfile PROC
    mov currentHash, 058942A5Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartProfile ENDP

NtStopProfile PROC
    mov currentHash, 08F1B7843h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    mov currentHash, 036A72F3Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    mov currentHash, 082C1834Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 07CDF2E69h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtSystemDebugControl PROC
    mov currentHash, 0D78BF51Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    mov currentHash, 04A8B16B2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    mov currentHash, 0188433DBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTerminateJobObject ENDP

NtTestAlert PROC
    mov currentHash, 066379875h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtThawRegistry PROC
    mov currentHash, 032A03229h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawRegistry ENDP

NtThawTransactions PROC
    mov currentHash, 0F144D313h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtThawTransactions ENDP

NtTraceControl PROC
    mov currentHash, 00552E3C0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTraceControl ENDP

NtTranslateFilePath PROC
    mov currentHash, 0873F6C6Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    mov currentHash, 03FA60EF3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    mov currentHash, 016B73BE8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadDriver ENDP

NtUnloadKey PROC
    mov currentHash, 01A2F63DDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey ENDP

NtUnloadKey2 PROC
    mov currentHash, 0C7350282h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    mov currentHash, 099F2AF4Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    mov currentHash, 03298E3D2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    mov currentHash, 005966B01h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    mov currentHash, 09B1D5659h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    mov currentHash, 082400D68h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    mov currentHash, 062B9740Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    mov currentHash, 05DB24511h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    mov currentHash, 09AAE3A6Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    mov currentHash, 03E9BC0E9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    mov currentHash, 0EB0AEA9Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    mov currentHash, 0C091CA00h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    mov currentHash, 0219FDE96h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    mov currentHash, 0203804A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    mov currentHash, 0DA4C1D1Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    mov currentHash, 073816522h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    mov currentHash, 01A0E44C7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    mov currentHash, 0DCB3D223h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    mov currentHash, 0144F351Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    mov currentHash, 04CD76C19h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    mov currentHash, 0009AF898h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    mov currentHash, 080953FB3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    mov currentHash, 01B2074B2h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    mov currentHash, 00E088D1Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    mov currentHash, 0B8299EB8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtListTransactions ENDP

NtMarshallTransaction PROC
    mov currentHash, 032A62A0Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMarshallTransaction ENDP

NtPullTransaction PROC
    mov currentHash, 0040B2499h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    mov currentHash, 034AD2036h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    mov currentHash, 05B896703h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    mov currentHash, 0D19DFE2Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtStartTm ENDP

NtSetInformationProcess PROC
    mov currentHash, 096288E47h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    mov currentHash, 02EA1223Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    mov currentHash, 0904BB1E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    mov currentHash, 0B6AEC6BBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    mov currentHash, 068A5287Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtManageHotPatch ENDP

NtContinueEx PROC
    mov currentHash, 0D34D0411h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtContinueEx ENDP

RtlCreateUserThread PROC
    mov currentHash, 0B4AF2B95h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
RtlCreateUserThread ENDP

end