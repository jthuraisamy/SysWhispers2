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
    push 0A9019EDBh
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 0279B1D25h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 0A63D2532h
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 01BA32709h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 09AA0BAFCh
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 0068C251Ch
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 04098542Eh
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 064F2B7C6h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 0F1DBDB5Dh
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 04EA84E3Fh
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 076E47870h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 06AF2899Ch
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 020B11F12h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 0F65ABCF3h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 00E910704h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 0DC482529h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 0043FDD12h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 03EDFC498h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 0249C4949h
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0271BC085h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 0DF41D0DBh
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 0D138E3EFh
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 00B173288h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 0221CD262h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 00F8D111Bh
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 0802C8FB1h
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 0408E5C41h
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0BB3FEDFBh
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 08D1F6008h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 003997D1Fh
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 0E570FAFBh
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 020A46D7Ch
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 08792109Ah
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 0D37FD6F7h
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 043916F45h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 0015B9873h
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 0705F2C9Eh
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0D554CCD8h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 09C38540Eh
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 00E962FC5h
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 076B1B6EEh
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 012813051h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 06D6F33BAh
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 0EFAF0A3Fh
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 018A10E0Eh
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 05BD20D17h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 01B285B10h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 0B0A9F414h
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 051F84F55h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 009AF4870h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 02A846226h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 04EC24853h
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 03F9EFEB8h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 00D930D01h
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 01853EA17h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0BD978D3Ah
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 064F5222Eh
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 00F9918F7h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 01A95928Ah
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 0E45F2C03h
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0615895C9h
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 06ECF6752h
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 009BD1F23h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 008821906h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 03DA3650Ah
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 07B10817Ch
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0DEB435C7h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 0F5D7FA65h
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 014CF7017h
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 00397CDCAh
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 01DB03E29h
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 051034E68h
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 0ED742BD5h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 0BC9BE029h
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 070FA7E52h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 049A1B3E7h
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 09210A0AAh
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 026BC2015h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 0E5979949h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 0BB18B18Bh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 09C35BEA5h
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 032927E31h
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 00C179F28h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0B805B2AEh
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 09E9CAC04h
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 0F8EB1CFCh
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 0CECA5FFBh
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 02B38D976h
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 08F30935Fh
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0119D2D13h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 088151919h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 0A4EAB262h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 00EAC1F08h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 066B04663h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 08ACE4995h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 0B5A0C75Dh
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 00394393Ch
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 052FFBBAAh
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 056F9586Ah
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 03EA31E2Eh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 018340882h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 0EF5AE9E7h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 0A59AF542h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 0A174B5D8h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 01984096Ch
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 0A041F6E5h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 039E51CB5h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 0CE9B043Dh
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 07C47E779h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 0B32F1E2Fh
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 03DCE1F48h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 07A5A04B7h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 07BE31438h
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 01A8B1A17h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 0A089F253h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 0E0B31EC1h
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 0BA95AB2Fh
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 062CE7F66h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 0A7A86A9Ch
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 024BEC0D1h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 0B2AC56F7h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 07AC96C79h
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 08A0CB78Bh
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0B690DB09h
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0F2E819B0h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 02ADB045Bh
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 0F7D1CC5Ah
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 00EB20922h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 0A832B99Ch
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 0E47FFFF0h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 05CF17968h
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0D5B5DA29h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 08C205696h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 0BAABDCBFh
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 013CCD0F0h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 00E5405DCh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 06CF789E6h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 0008E2FD3h
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0D74AEEEEh
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 00C31852Ch
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 00833388Eh
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 01A961A3Ch
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 09089DC52h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 0F6C68015h
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 0E81515BAh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0881D8E8Fh
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 038AC002Eh
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 0C226DBA2h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 0BAB5B825h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 008802FD5h
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 0218E320Ah
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 043D94753h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 040920046h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 055DD3B01h
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 02172C21Dh
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 01494070Fh
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 03CB1253Ch
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 00BAA2533h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 002BCEAC0h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 01AA5E4D8h
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 07C7C820Ah
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 0C691F25Ah
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 03FD91D8Fh
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 010B64E7Fh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 03D851B32h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 0030C65D9h
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 08CA1E65Eh
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 082031A2Fh
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0168A9797h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 0FE40BF96h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 0C3A1CD3Eh
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 0A7B12F95h
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0D34E2848h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 068F88CA2h
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 0D17C3A7Dh
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 08D2CE5F6h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 0A276A3FAh
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 08C2F4972h
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 03F9D2DF2h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 004847E04h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 07A804447h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 084ABC67Ah
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 078228069h
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 078A6B50Eh
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 008199015h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 014AB4C6Ah
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 073D6416Ah
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 019A559ABh
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 067C0594Ch
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 086830DB1h
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 0D099D60Dh
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 005222F9Eh
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0953FAE90h
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0F7C28B29h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 066B24F6Eh
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0F4B2FD20h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 004951C72h
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 0E03DD9B1h
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 0769689CEh
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0E27EE5ECh
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 0018D35C0h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 00F827B0Eh
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 0E245E0DCh
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 09F2B8EB0h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 098DEA590h
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 03E90470Dh
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 006FB3741h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 0C3793369h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 0ED431050h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 0E9C0F37Eh
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 07ECE6A5Eh
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0E0BAEB2Dh
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 0B029493Fh
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 02D911828h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 0E153F3CCh
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 043531F97h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 0CEE626CDh
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 09F90DB3Ah
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 0048E3803h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 007921D1Ah
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 00C875654h
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 00AA9CC97h
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 01FBBD112h
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 01526D977h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 02D9F0A32h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 0E8B9EE28h
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 009A2794Bh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 06DB47D2Bh
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 012B3FAA8h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 0028F15E3h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 0811EB399h
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 064F8ABA4h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 046CE265Bh
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 01CF8EEE9h
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 00CA2F4E8h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 0DC4B2131h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 03090393Ch
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 01DA1010Ah
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 0C12FC2B0h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 0399EF43Fh
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 07AD39C47h
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 01F884540h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 09059EACAh
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 01F810F3Ch
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 026872421h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 0D48B0A2Eh
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 09C00BB9Ah
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0DCCD25BCh
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0100CF11Fh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 082891F8Ah
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 0839EC332h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 06171987Fh
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 0BEA4C9A5h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 042999034h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 090CD6BA9h
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 0407CC165h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 0253C6F20h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 00B19CF44h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 078F0547Ah
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 032D62CB5h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 01F27FA45h
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 0CD5FC9D3h
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 0A4BAAE24h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 0849C9E11h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 03CB1DE21h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 04CEE1854h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 049CF5E48h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 0B952E586h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 03D9B1738h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 00B961D18h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 0CD7BBBE1h
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 0689A244Fh
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 00AD3E8A8h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 0DFCEA82Ch
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 067CD4B4Eh
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 009A70C3Dh
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 05017B441h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 021544259h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 0C29CEC21h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 073D4BF60h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0130E9110h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 01C1E50DAh
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 03AB15D6Ah
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 03CB610E6h
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 06EAF6E02h
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 078E04669h
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 0AE126BB0h
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 0390D01A4h
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 0CE85EA5Fh
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 015BDE3BDh
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 03EB437D8h
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 0F56EF5F8h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 0A63B9E97h
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0EEC9E46Fh
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 00FCF7540h
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 0CEC5EA57h
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 0C415D4B7h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0B16DD7FFh
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 038A1DEAAh
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 00BA4CCFFh
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 01884040Ah
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 0086715F5h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 03497252Bh
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 01E5000FCh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 01F91F00Dh
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 02F57C91Ah
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 08C9AF84Ah
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 082BF8928h
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 0A81B85BEh
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 0DD40F219h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 07A15AA30h
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 016B43DF8h
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 0C5597C59h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 0E73AEDA4h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0AB9A9331h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 01E3E991Dh
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 09CC89062h
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 0FE692358h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0A61EB9A5h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 0861B979Eh
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 014BF0E31h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 01AB53D1Eh
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 00B331392h
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 0E14D0A1Bh
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 086259A8Fh
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 0FE6EECE2h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 0EC0EED97h
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0EE59C6CAh
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 09E07A285h
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 03CA4E8EAh
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 031982403h
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 0004F01C5h
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 045DD4A42h
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 0399CF9E4h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 01C025DDEh
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 06D3D3189h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 0E2462E1Dh
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 02A3454A9h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0ECDAD36Dh
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 0F4181594h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 0869E8C00h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 014A2E2B2h
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 0F811056Bh
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 0F69123CFh
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 00C9A0C0Dh
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 0A707AC6Dh
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 00E907213h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 0C4D91783h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 03AEE15B3h
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 0C24EE0DEh
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 04C562F41h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 0AF92DC15h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 0B267D89Bh
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 0098E6716h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 013851510h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 036F4733Ah
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0C04AF9FEh
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 069404395h
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 0849743E9h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 058A1B6F6h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 063FC9FF8h
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 02991E0CAh
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 0A9E78850h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 0A834A2B2h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 0BA38AFB8h
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 010B22D1Ch
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 068CB6B5Ch
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 00CE1FABEh
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 0CBF2AE6Dh
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 065DB6654h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 0C649C6DBh
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 058B47036h
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 009A32A34h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 01853DAFFh
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 0E6CDE257h
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 00FB2579Ch
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 043957E22h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 03BB0EFECh
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 061DA644Ch
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 064EE4140h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0ACF829E0h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 0714E07B7h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 0539F9DC3h
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 0309B7420h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 010ABA14Ch
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 0341FF936h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 00CB2781Ch
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 026B23B30h
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0353ACB21h
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 015BA1616h
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 0F248DAEEh
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 036812637h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 0C29395B2h
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 04C005881h
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 0139F1504h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 0795A51D9h
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 0CD50ECE5h
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 024B82225h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 09085B12Dh
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 0DE47CAE5h
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 041D54261h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 02B95753Ah
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 09813AA9Fh
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 07B2363A2h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 042535CB7h
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 04890306Eh
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 082157840h
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 04AA27069h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 030CAC6B4h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 01E87311Dh
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 010B3CCFDh
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 062AE067Bh
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 081155931h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 0A698883Ah
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 035265E32h
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 0EF14186Bh
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 08C97D237h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 0F5B40CE8h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 09A8EA717h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 026DDDD82h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 03F979F01h
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 040AF6214h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 0009A624Fh
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 002401EFFh
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 0D647E8D4h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 0F06B1976h
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 004AF2B3Ch
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0C096F42Bh
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 0C69CC001h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 088D6A466h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 0FC240D70h
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0049DC2C0h
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 0FFBE08E3h
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0FC20DBBDh
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 0301F3CB6h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0C09401C2h
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0FB9B1A17h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 0F451E4CDh
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 04CCE691Eh
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 01A8E0C1Fh
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 0F6A4904Fh
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 073AC7F4Fh
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 09A144750h
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 0A79B76AFh
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 036A713F4h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 0AC00B581h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 02DACC778h
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 093812F45h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 0D960EF3Bh
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 0001260FCh
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 052D09268h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 08425F188h
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 0FC4209D8h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 00751C1FBh
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 060B6106Ah
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 00A801B24h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 080AAE94Ch
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0871AAFB5h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 001343783h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 01445ED32h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 074AD6802h
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 09338D3F4h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 04CB423A9h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0173117A3h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 0C881F62Dh
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 0DA42DCD5h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 0449813B2h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 050B393E9h
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 0C888CD1Eh
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 098B99A2Fh
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 015B77575h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 000AA223Bh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0C02BE6BBh
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 0308CDA16h
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 00F952B4Fh
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0E24E0535h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 03994140Ch
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 005A52EFEh
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 0962DFBC0h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0BA3EB39Bh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 0130F9C29h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 073722FD6h
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 0A808B6B1h
    call WhisperMain
RtlCreateUserThread ENDP

end