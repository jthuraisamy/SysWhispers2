.686 
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

NtAccessCheck PROC
    push 0A8128191h
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 007ADF9AFh
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 0C172C2FDh
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 041F01F39h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 01AFD7E0Dh
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 0BE0C7F22h
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 0AA3A98AEh
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 0C058080Eh
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 03E3DD038h
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 04AE42A7Bh
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 072E84BB4h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 026B5213Eh
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 0A0B2DD52h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 0BC9874B7h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 032F00B54h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 002961525h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 03AA63205h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 054C4CFF0h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 03CA05F3Bh
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0BD9CD07Eh
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 068FD6D68h
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 0C3A2FB66h
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 057E24A75h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 067DF6042h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 0910B898Bh
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 08D2780BEh
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 0108E165Bh
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0F864F4FEh
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 066F99583h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 001D1337Bh
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 05C8F5710h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 030AC353Ch
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 08D96F719h
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 064C94B1Ah
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 08B2387A7h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 01550885Bh
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 03317FE3Eh
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 001A7062Ch
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 0D97CEFEFh
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 0F66AF6F9h
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 078BF4676h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 01297EC1Fh
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0058A6375h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 005BF0620h
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 006AC7662h
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 023AC3B27h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 01F0B49D5h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 0190659CFh
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 023B5C5A1h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 061DB0804h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 068C06462h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 056CF9A95h
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 0593BA37Ch
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 0D436DEABh
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 0D601D693h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0118B0128h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 027BED925h
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 01D931513h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 068AFF4A0h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 0180666FBh
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0C6D85AEEh
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 00AB72B02h
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 009991EF7h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 09B009C9Bh
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 05D991144h
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 075D0474Ch
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0D940C5F3h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 02DB33010h
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 00D51D5F5h
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 0C6C10899h
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 046AD334Ch
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 00EC5095Eh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 075348F71h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 00A96020Dh
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 0F05BFEF0h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 01D96E0DFh
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 06B933746h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 02C87B6B9h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 0AF947F26h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 011B0213Fh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 0CE99E44Dh
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 06CCF286Fh
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 09EB25E91h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0C519B1CDh
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 08C9D8236h
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 0E6432F06h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 0C303B7D7h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 02C08249Fh
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 01EB6DA9Fh
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0B6548CDAh
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 00CBE7E53h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 05AFB6C26h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 032AA3722h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 03EAA19FBh
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 00F1BEC81h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 01381FE9Ah
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 01FCB2968h
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0A62DFA16h
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 0F6779AEFh
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 09A5E9ACCh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 08F836581h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 0189BCE26h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 005E1375Ch
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 00DA40524h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 039951532h
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 0AF2E91A2h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 007910501h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 02D102DB4h
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 0043F9701h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 090AB2679h
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 059ABE3BCh
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 080BE0EA3h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 00DB23C0Ch
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0E8493916h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 0A680EC52h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 020B11F1Ah
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 02D8CBAB4h
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 066B12972h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 0CFC29B1Eh
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 0E6B218D1h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 08C249097h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 02C433EEFh
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 06AF74D49h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0AF34BCBBh
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0CF58EFD6h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 0129E3A53h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 03CAC011Bh
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 031AD240Ch
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 0257F3CD1h
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 03EB22728h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 0BEAEA12Dh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0555B2ED4h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 0922ED281h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 0846AF28Fh
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 06D4DE278h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 0ED33EAA1h
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 05CFF6334h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 01088161Bh
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0298D5456h
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 011C57F58h
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 0099D372Eh
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 00691E292h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 026DCE4E6h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 038B80DEAh
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 089922D44h
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 081BCB51Fh
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 0609F0A52h
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 031B6CEF5h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 012573C88h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 0DEB2E41Ah
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 05FEA5A5Ch
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 0F7BBCD37h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 0168D4C4Ah
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 00159C709h
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 024B3C320h
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 0EB5D1729h
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 066B15D1Eh
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 09D94E71Ch
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 0BD97E7B9h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 0F4C6D27Ch
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0AAB814BEh
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 0CC2AA920h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 051B1703Bh
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 0113C37ABh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 0C79CDE37h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 004AE647Dh
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 088D466F9h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 010027AFDh
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0A069EAC6h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 0462C49B6h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 0152F77D8h
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 039B8E399h
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 046C8495Ah
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 03FA7A693h
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 028E9762Ah
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 06D4A31E9h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 0E073FFF0h
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 04C6C125Fh
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 06DB70A24h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 010B1EAE0h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 06A51BC0Fh
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 09F17DBC6h
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 0E6BFA26Dh
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 0BF2F87B3h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 002BECEC1h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 03C3F60EAh
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 019937350h
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 0498AB203h
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 03D853366h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 006E2B2DEh
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 052C9505Dh
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 006067284h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 08C1297FBh
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0351B1980h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 020B6011Ch
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0F6D07EF2h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 04096520Ah
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 00D9F223Ch
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 022A8C1E4h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0F25ED7CEh
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 00D84F7F6h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 041105F96h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 0C265C2C2h
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 037E36638h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 058DF5E4Ah
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 029B9D324h
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 016423FF2h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 0278FB8B6h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 0CF95B474h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 07BAE7100h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 0869AE88Dh
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 012CA5D18h
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 027B6ACA0h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 02893A18Fh
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 01B5A14C1h
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0D2638E87h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 026BA3427h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 0C673E4E7h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 004AE003Bh
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 025A13B2Ah
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 09E88E876h
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 008ABCBD0h
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 00D9F3BC2h
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 0B3A745B9h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 0AC998D31h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 0389B184Eh
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 00193E7FDh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0CD983AFCh
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 007BF7C30h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 0C4D541D8h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 03F9A055Dh
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 0109C5840h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 0000E0493h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 014906E29h
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 086B0AA12h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 0ACA3F47Ch
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 035BC6571h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 0DC4FD6D5h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 021955078h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 0544840F7h
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 03A5027DEh
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 0299F4566h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 0E6E918FEh
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 0BC8A8828h
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 014AF5C03h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 06AAB6A46h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 0ED57A68Fh
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 040D93A25h
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0C05FA28Fh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 032BED13Eh
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 03BD67B73h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 020B2A9B0h
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 012985840h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 0E28BD026h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 0E45FDEFAh
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 06CDB5169h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 005B7FC30h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 035B3F18Fh
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 058C7AA9Eh
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 046DEACC1h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 05987643Ch
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 01F890917h
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 008A65459h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 0E538EFA6h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 0220D60D1h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 032AC241Ch
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 0019D2A06h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 080934EC4h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 00995150Eh
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 08612B2AFh
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 0F0DABA7Dh
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 05CA71E7Dh
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 017D37C02h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 051BF4C3Eh
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 02188C39Ch
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 0A9369695h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 0931DB584h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 0055803F1h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 0BE21868Dh
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 0559AA1E6h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0F05D868Ch
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 0E0D1B009h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 0C002D066h
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 0328FAB8Ah
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 0EDACD1E5h
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 0D64DB65Bh
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 0349C3B37h
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 017AA8CA3h
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 00A920C07h
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 0704F5914h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 0168A380Ah
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 099017F48h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 0869E71F2h
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0AA8DA427h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 0098D7702h
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 0C40FE4DDh
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 0863E5E75h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 00393678Bh
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 00AA6438Ah
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 00892FCF5h
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 07CC81FC6h
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 0291A50EFh
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 074D82B11h
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 014BA102Ch
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 0F6BB132Dh
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 05ABAA5E0h
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 0064126DCh
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 002092BACh
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 01EB2C316h
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 008B30228h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 03BAD3921h
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 0EF00D191h
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 064472E85h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 0F846CAC9h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0DC41CAD8h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 0BE91F6B2h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 05AC43A4Eh
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 04CD34942h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0FB3DE888h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 00FB33404h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 00D14F366h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 0A53EAABDh
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 05F9F7302h
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 074EE5277h
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 01C2716BCh
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 006960802h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 0F7D4A874h
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 00B5FD1EEh
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 0756D15BFh
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 032D30D4Ch
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 06C533989h
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 0249814DCh
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 03B87141Ch
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 0D59AEA3Dh
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 0C759DEF0h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0289BC688h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 03D85232Eh
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 0802AF0E1h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0EA5EC38Fh
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 016952E40h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 0183666FBh
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 01414871Ch
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 013084FDCh
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 01E9DC9C2h
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 0F0DBB1F4h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 063CCB579h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 060C84659h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 07EA4BAD9h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 074E47C75h
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 001AE1B3Bh
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 00FEA0079h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 089C08E53h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 0B5A2E366h
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 0B6A39231h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 01FB51F26h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 066B66F22h
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0515A3ABCh
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 090A445FEh
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 06C9F106Ah
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 04A287B62h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 08D1DEAF0h
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 09D8340A3h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 0E552E4C8h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 022B32E30h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 06141AF1Ah
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 022B63F18h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 00EA4E836h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 022F36A52h
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 035DF0868h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 0B5A75637h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 0DE54DEFBh
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 0BE2A59A8h
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 073A23469h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 0228BFC3Bh
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 00048C61Bh
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 0B196A115h
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 0DB98F832h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 059AC6914h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 027C31C6Ch
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 0228D4162h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0DC4DC2C7h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 0150A820Bh
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 00F99051Dh
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 0909DD840h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 0D00D7858h
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 0D4EFCE49h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0E14CCFC5h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 07CC86D26h
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 004A6541Ch
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 024B2D833h
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 00D96070Fh
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 022B85E5Eh
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 09413988Dh
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 0D053FCCDh
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 0195A04D9h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 0388609CBh
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 079452B63h
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 01EB0082Dh
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 0A52582B8h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 06BD2B572h
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 0EE599C9Eh
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 03388614Ch
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 09E08C0C5h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 009B15690h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 00B901DFFh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 08F4297E5h
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 078224EBEh
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 076E9163Bh
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 060D32C06h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 02494CFE8h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 0E2B11A3Bh
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 028D05C31h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 0091AF90Eh
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 008A40039h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 095051921h
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 01C24A919h
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 0DC47DED7h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 066B64076h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 0F52FEE9Eh
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 01813892Ah
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 077D53045h
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 0369D4C5Eh
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 09E01BE8Fh
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 08D3C8D80h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 039A2C7F3h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 063A27A4Fh
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0869AD120h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0120F34A2h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 03B58CD3Ah
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 01C36F24Dh
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 0D01A01A0h
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 000BAD080h
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 060CD5D50h
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0219B2214h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 0309C0235h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 02D822D29h
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 012D2EF80h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 008A7C7EBh
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 0D45FFB84h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 03AA92035h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 0E5370D6Dh
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 057CC775Bh
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 072D04892h
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 025BFFA8Bh
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 0169C2ED6h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 078AF91CFh
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0B7D6EDBAh
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 0CB609FBCh
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 0D6272648h
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 007910D03h
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 06288A0F2h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 0E35E2DF7h
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 066CDF8F4h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 00F8C370Bh
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 00A95B982h
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 06EAA4D1Ch
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 0208D635Ah
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0F8A2D474h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 0A432D8B3h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 09633F6E5h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 0D64CECC6h
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 0CA110345h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 0463560A1h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 05B403FCBh
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 01E803815h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 008A20831h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 0B4B823BBh
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 0809AD644h
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 008AA2B3Ch
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 0D88A02DCh
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 0198C4B2Bh
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 0108A3217h
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0148D3017h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 03EA35238h
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 03CB53824h
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0F05C1727h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 001AB0A34h
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 00C6322BCh
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 098AB068Fh
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0972EA4B6h
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 09CA15581h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 01CB3A186h
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 094BFDA95h
    call WhisperMain
RtlCreateUserThread ENDP

end