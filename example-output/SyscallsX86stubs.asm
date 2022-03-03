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
    push 0C567DEC8h
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 097AFED5Dh
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 062F67F5Eh
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 00B9F29CBh
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 08AA6F858h
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 066EEE9F0h
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 0C09BE6C6h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 0CCCBCB51h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 07AAD621Ah
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 018D31E4Bh
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 0F764F907h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 066F40F6Eh
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 02CB63F18h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 09A45D497h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 04ECD3700h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 0F150063Ch
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 00A252A99h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 0821B5420h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 0B216510Dh
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0162907B0h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 06CD8694Eh
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 08C2FCA8Eh
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 02D995062h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 05B9BB8F1h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 0B9D24DBDh
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 072288248h
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 08C920945h
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0538C2B67h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 0A6F38925h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 01B950137h
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 051B13C6Fh
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 0FF4E3408h
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 0839BD950h
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 0A13EA2A1h
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 041987323h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 015A36724h
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 09837C289h
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0E684F928h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 02298B6AEh
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 04A886051h
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 0923894A8h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 088C3A811h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0699C337Fh
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 02B21D56Dh
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 0C549C035h
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 005AE0F37h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 072848CF2h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 01C855A7Ah
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 0BA12774Ch
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 0261BB701h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0667D6FDBh
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 0CE50321Bh
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 0A8BA52AFh
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 0DE4FF81Bh
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 008AC2DF7h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0152F460Eh
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 0B6A58C32h
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 0C92C5B37h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 010D7D480h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 01EA037FDh
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 018832E12h
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 008E0017Ch
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 00F9D3B11h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 0900B89A6h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 01DC69FFAh
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 005911530h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 03B5A0286h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 0E54A31FBh
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 0FB5CA1E2h
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 0B36EF3BCh
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 0B6A2B532h
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 0509377C8h
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 0811BB58Fh
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 0FB30D7EAh
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 06D7AFD42h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 03DB26101h
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 0916CD3B6h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 0AC94B22Eh
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 0A912B9A7h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 07DD1795Dh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 04A826E51h
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 0F44D6875h
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 03288FD23h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0669B900Ch
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 0F65DBC8Ah
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 09805F5DCh
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 0C5BC2F31h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 0269C7021h
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 0DE51D8C4h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 00199090Bh
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 078550AAAh
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 0984CE496h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 0980BFD92h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 08617E083h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 0BA0297B7h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 0881AA483h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 00390EC8Ch
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0346BBF45h
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 0C839C0A5h
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 02AB7EBE2h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 0C74B35DCh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 0E65A6E77h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 08B91F554h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 017860F16h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 01B962F1Ah
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 00390F30Ch
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 039E91CBFh
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 0C2E5C447h
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 0348F2836h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 020B3740Ah
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 00182D2B5h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 027150D4Bh
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 03FA14842h
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0F7513A10h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 0746CAB4Ah
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 0F0B2C31Dh
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 011895A38h
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 0AB2EA0B1h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 0819FC721h
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 046B43F5Ah
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 0CA92CA07h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 0F31FDBD0h
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 03C7D2FE7h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0FE6BCBCAh
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0F2E819B0h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 0EE63F8D3h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 036F7550Dh
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 0F742E2CBh
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 02E335DDCh
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 09033B39Ch
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 021B10C2Fh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0862887B7h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 01F0FDBAFh
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 00AAA15C7h
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 0E5D0F961h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 02CB43324h
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 060F25960h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 008920A07h
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0FED0E962h
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 06AB40BA9h
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 08BDDB351h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 03CD20840h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 068DABB81h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 02A4C22AAh
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 00B92701Fh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0785D1ECFh
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 0CB5F3B03h
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 009C72C5Dh
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 0CC07CA97h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 00CE22DADh
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 045CD5E26h
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 09C228A8Ch
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 0CE54E700h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 0BC34FAE6h
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 060AE194Ch
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 078EA958Eh
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 022B43B1Ah
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 049E1477Dh
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 016BBFEC7h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 024900C27h
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0AAB6F410h
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 0705FFC74h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 0006101EBh
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 0C016CC8Fh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 007CC2F96h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 0C9A7A17Dh
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 00AB5FAC9h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 090A25EF9h
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0036DFA70h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 00E972732h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 07BC54D42h
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 026B8758Eh
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 076E8797Ah
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 06F7937CDh
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 067075792h
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 03A8DE3C6h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 02ABF3130h
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 004BFD18Fh
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 09E3F8F53h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 083395701h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 0D438184Dh
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 0D64FF61Dh
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 0E1BD10C1h
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 0048AD7C4h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 0AC942689h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 082BBDE5Ch
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 00597888Ch
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 08992469Ch
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 001998882h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 009184DC3h
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 00C962A0Fh
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 09B255778h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 08F1E8E8Ah
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0BB9C9BC0h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 0A475C5E8h
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0F4DBEC68h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 08514A943h
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 0FED3C77Ch
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 021373CB4h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 062FFAFA6h
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 05D86490Ah
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 01B890B1Eh
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 01E9896AEh
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 0B93CDAC6h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 0D6B9FC20h
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 014B0C5F1h
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 0880D707Fh
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 05EC63056h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 026B45D53h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 025B30AE0h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 094BB4E0Ah
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0294F3ECCh
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 02D3DA11Ah
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 0A41FDDF3h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 0E0BB38F4h
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0FDA839D4h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 018896A47h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 08E59B2FBh
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 008E22C77h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 0BB959111h
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 020827258h
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 00838CA6Dh
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 03516A02Ch
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 075A746F1h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 0E4E60E86h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 006981DF0h
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 09DCEB368h
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0F9A1D319h
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 04DD47254h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 0009D2631h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 00B5AF531h
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 02E9B6020h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 0F0AFF302h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 01BBF471Eh
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 01A3B68F6h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 062CDA176h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 090BE0381h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 03C95A8B1h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 0C5ADC421h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 017BCD314h
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 02F15CA02h
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 0A8025F07h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 00AAA9D9Ah
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 03582EBCAh
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 02A1224B8h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 0549DADC0h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 08B395B96h
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0F26E190Ch
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0004D05DEh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 004800126h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 0B19B25A0h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 026AE273Ch
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 030BD5820h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 0F63EC16Ah
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 01281E8E2h
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 0942C7B7Bh
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 0EFB8191Ch
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 0D1571D22h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 0EC7B1EEEh
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 055B54232h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 0F3411B21h
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 0DA4BF2EAh
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 086B4AEE8h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 0163B3E87h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 030AB1633h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 0F47EE4C4h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 087B28039h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 0CAD8F862h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 0019D3522h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 0CBD7DF78h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 05830A866h
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 06A562CE8h
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 03AFE5F24h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 08214ADB5h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 00413CE4Fh
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 024B5D6D2h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 0A335B9A0h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 04CAA4C39h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 098860598h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 0ED1B315Eh
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0207C68D0h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 048AC8AF7h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 018930502h
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 00A8DE4D7h
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 00A866446h
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 00A900A7Fh
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 02281ABADh
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 025D9335Ch
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 08A218AB3h
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 007222F99h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 004AD2E60h
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 049918EC8h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 02496120Bh
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0644C2AE6h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 02D1F1FBCh
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 07F577DFBh
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 08AA19E07h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0895C1557h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 03AB0230Eh
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 01944FE1Fh
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 0BABEA832h
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 09FD37E85h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 0069E731Dh
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 02C34D75Bh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 056B95428h
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 07AD0AB6Ah
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 07657F04Dh
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 0605205CBh
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 0F4CC68D9h
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 00B89D1C1h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 0A220AABCh
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 05ED4AF4Ah
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 0F6143852h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 02C1E04A2h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 059832B63h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 032926FA4h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 062B89AEEh
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 0A23D83A0h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0BC109E57h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 0DF42D8D9h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 01306FD64h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 0AE30AFBEh
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 0FF67117Fh
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 01C075CA9h
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 091A3118Eh
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 0548C6E30h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 0A80A252Fh
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0D7432B13h
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 00D660DF5h
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 0C29BE958h
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 06FFAB1ACh
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 09454F1BCh
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 0EA5A132Dh
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 01978DC05h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 0DD9F3A0Fh
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0AE38A2AEh
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 0195203DEh
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 0C49C3FF0h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0F14BD514h
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 000AB2CECh
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 005A17B6Ah
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 04C8C0F24h
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 043A90D6Ch
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 05655156Eh
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 03CB7DE3Bh
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 022B8C8B4h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 0140F761Bh
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 0A4B178F4h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 08528457Ah
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 017800B15h
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 011BB2C19h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 0D5509485h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 09B008980h
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 00A30921Ah
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 01389F09Ch
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 0A2B3DBBEh
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0C1ABC43Ah
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 028881C2Bh
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 000995444h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 054A936A2h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 0FE2B117Ch
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 095B760D7h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 065D37A46h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 0168A2E3Eh
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 0A135809Fh
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 03E74FE27h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 00A8D1B10h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 0B062FCC6h
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 08B2BA68Dh
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 049D74A58h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 00E98EDC9h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 03A37CC5Ah
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 027820435h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 07EA57E37h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 0148B3415h
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 0032E2972h
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 07BCD467Ah
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 03BB10F0Ch
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 0E30AFEE4h
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 0A430BD9Eh
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0D849DCD1h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 01F3CC014h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 0CA54E8C5h
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 06E2A68B8h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 0D6441CD0h
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 054CC4E75h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0534DCD76h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 010B03D2Eh
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0E138106Fh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0D79037CDh
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 0DA453658h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 064B36A56h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 0143138AFh
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 08E10B29Dh
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 03D9F4F7Ch
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 0E0DE9052h
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 0118B445Dh
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 0B8999025h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 08E1BB9A5h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 007B31316h
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 064FF606Eh
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 089C88354h
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 098C25B96h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 0A1906FCDh
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 00F94F6D7h
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 036CA6C1Ah
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 058FF66AAh
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 01A801BEFh
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 0B96F3D52h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 0D68303C3h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 0A0B9D0BFh
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 000955853h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 0F4753E22h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 01A345499h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 0028EDCBAh
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 0EE352F4Fh
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 096079C93h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 0EE10D89Ch
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 0E6CDF676h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 0EC12C752h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 08F930E5Ch
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 0FB1B2E47h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 00C824C55h
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 0A2225C41h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 0AC3B2B18h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 030AA1F30h
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0A261FE50h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0C49239F7h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 00438CC65h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 06EB46C2Bh
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 00C5A877Dh
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0079ECDBFh
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 0930C7015h
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0D718FE84h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 0BC97A629h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 005902D13h
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0D83EE894h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 00E91464Dh
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 07CD77D5Ah
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 0048D1A29h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 0F06EE30Eh
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 0F7A01536h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 076B70B72h
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 00FB35E07h
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 0329D2E30h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 005DC6047h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 042D9CA0Fh
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 07598A5C0h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 08D48FB53h
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 00F9F1AF1h
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 020D21268h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 0E1449E99h
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 0B41C4A40h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 007D4075Fh
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 00C32A8F2h
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 03095DD04h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 0CF42D4D5h
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 078AC6832h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 0239E390Ah
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 0F0DEA609h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 0D394DB0Ch
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 0008AF987h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 01A8E0407h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 08318838Ah
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 08447EEC3h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 020964247h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 056A8B6E6h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 02CDAF18Fh
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 0D18BEA3Ch
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 0008B0F18h
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 0157A71A9h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 00CDE1A7Bh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0F817D885h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 0D88403CFh
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 00DA72AFDh
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0478A0178h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 0802C9FA1h
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 03597497Ah
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 017A3FBD6h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 08AA9A1EFh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 0A272FAD2h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 037DC7506h
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 072DD3873h
    call WhisperMain
RtlCreateUserThread ENDP

end