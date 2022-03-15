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
    push 0FA40F4F9h
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 011A63B35h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 064F17B62h
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 0238A0D17h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 0009E3E33h
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 0168C371Ah
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 0C544CDF1h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 022342AD2h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 0E97AEB1Fh
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 0088E0821h
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 034A10CFCh
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 0ACFE8EA0h
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 062B0692Eh
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 00A2E4E86h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 058924AF4h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 00352369Dh
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 08CA077CCh
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 0A635B086h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 00F1A54C7h
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 016AB2319h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 03565D433h
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 0025D728Bh
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 008172BACh
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 0E15C142Eh
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 01F88E9E7h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 0D99B2213h
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 08E9DAF4Ah
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 02B907B53h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 07EC9073Bh
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 0099E0519h
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 060F36F68h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 02D4A0AD0h
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 035AA1F32h
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 0E273D9DCh
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 09514A39Bh
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 0F8512DEAh
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 024881E11h
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 006AC0521h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 0CA7AC2ECh
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 004960E0Bh
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 00F2EC371h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 0568C3591h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0A25FEA98h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 0FE26D5BBh
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 030863C0Ch
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 0159C1D07h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 02FBAF2EFh
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 0791FB957h
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 037D24B39h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 0B6AE97F4h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0AD1C2B01h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 0520D529Fh
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 058BBAAE2h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 054CD765Dh
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 00A9E284Fh
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0179F7F46h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 06AF45662h
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 005953B23h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 05CDA584Ch
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 03EA1F6FDh
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0DD5DD9FDh
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 0200B65DAh
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 0071473E9h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 030D52978h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 001940B2Dh
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 06DD92558h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0009CD3D0h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 013C5D178h
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 02E8A0C2Bh
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 014B63E33h
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 022BF272Eh
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 0B0B4AF3Fh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 0E5B3BD76h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 04EC54C51h
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 06CFB5E2Eh
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 0FD6DDFBBh
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 0B998FB42h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 0AF8CB334h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 05CE54854h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 00F940311h
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 002EC25B9h
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 07D5445CFh
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 0228E3037h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0A23EB14Ch
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 02A9AE32Eh
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 02AB1F0E6h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 09DC08975h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 03C802E0Dh
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 0DD42B9D5h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 061AD6331h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 0271915A7h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 0821B7543h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 0CAED7BD0h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 054C25A5Fh
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 01DC11E58h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 001A23302h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 005977F7Ch
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0D442E30Ah
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 07EA17221h
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 0552A6982h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 099B41796h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 01A8958A0h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 09390C74Ch
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 005951912h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 03B67B174h
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 025971314h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 007900309h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 0A48BA81Ah
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 01CA4540Bh
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 0B8A26896h
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 0FFE51B65h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 018B4E6C9h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 019BF3A24h
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0338FFDD3h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 0C8503B3Ah
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 030B2213Ch
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 073D77E7Ch
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 03EB1DDDEh
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 0636DBF29h
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 0194B9F58h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 0C4F5DE41h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 0389F4A77h
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 02CA81D13h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0FA1DE794h
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 00C982C0Bh
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 01888F4C3h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 056EC6753h
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 008B3EDDAh
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 022B5D93Ah
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 02233A722h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 0D836C9DAh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0C654C5C9h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 0F85F36EDh
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 0024618CEh
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 0A40091ADh
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 040998DC8h
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 022B2A5B8h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 0C897E64Bh
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0D65AEDFDh
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 0FF2A6100h
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 007B22910h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 08736BB65h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 0F758392Dh
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 0256033EAh
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 003A35E2Dh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0BC9C9AC6h
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 00C9007FEh
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 0164B0FC6h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 004B43E31h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 018813A51h
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 057BA6A14h
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 084648AF6h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 0AEF09E73h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 0F494EC01h
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 03A7637F8h
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 0782E5F8Eh
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 0A23C9072h
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 079468945h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 0009E21C3h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 0FAD436BBh
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0426E10B4h
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 0CA2FDE86h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 00F90ECC7h
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 012B1CCFCh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 0178C3F36h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 00E1750D7h
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 0F65B6E57h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 08740AF1Ch
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0A69A66C6h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 068CF755Eh
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 017C73D1Ch
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 0E47DC2FEh
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0FDDC08A5h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 0ED7AA75Bh
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 054C36C00h
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 0444E255Dh
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 02EB4CCDAh
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 009B1CFEBh
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 081288EB0h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 06E3E6AA4h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 0029AC0C1h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 0970FD3DEh
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 06E52FA4Fh
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 0FCB62D1Ah
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 083189384h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 096A7CC64h
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 0E58D8F55h
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 0B0684CA6h
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 0099F9FBFh
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 06022A67Ch
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 03CEE2243h
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 01BA730FAh
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0EC26CFBBh
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 001813F0Ah
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 0A97288DFh
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0CED0FB42h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 0089C140Ah
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 0923099ADh
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 05D24BC68h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0BED35C8Bh
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 0336B3BE4h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 033930B14h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 06EF46592h
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 03AEE1D71h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 016B57464h
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 02A88393Fh
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 036820931h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 032CE441Ah
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 0A8B02387h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 0386B35C2h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 076E83238h
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 04918735Eh
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 02DBE03F4h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 02C97BD9Bh
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 07CDC2D7Fh
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 053AF8FFBh
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 096B4A608h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 00E8A340Fh
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 008A20BCFh
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 07FD56972h
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 08E59B5DBh
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 026D4E08Ah
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 0A5BAD1A1h
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 00DAE4997h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 09ED4BF6Eh
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 0D83A3DA2h
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 08713938Fh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0A538B5A7h
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 0E5BEEE26h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 0069B203Bh
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 04FAA257Dh
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 076BCA01Eh
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 0148F1A13h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 00C9C1E2Dh
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 08E33C8E6h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 05AD599AEh
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 0A43BB4B4h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 07ACEA663h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 00DA3362Ch
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 09A3DD48Fh
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 0FF5DD282h
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 0EFB2719Eh
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 08AA31383h
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 03F8F0F22h
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 0FA202799h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 02C9310D2h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 0744F05ACh
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 034901C3Fh
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0C690DF3Bh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 0A4A02186h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 0D5EB91C3h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 0DCB0DF3Fh
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 01C9F4E5Ch
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 0074E907Ah
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 09F721D4Fh
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 03F1844E5h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 0DA270AA1h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 0BBFD8746h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 0E17FCDAFh
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 067E66A7Ch
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 0130628B6h
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 00B981D77h
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 0243B2EA5h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 0263B5ED7h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 008B1E6EDh
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 03917A320h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 01142E82Ch
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 0BE9CE842h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 009941D38h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 071E16D64h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 01999E00Dh
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 06B97BFCBh
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 0CB12AAE8h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 07F837404h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 0E78FE71Dh
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 0BABADD51h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 090B047E6h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 00C656AADh
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 0429C0E63h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 06BDD9BA6h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 010CD1A62h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 086AEC878h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 050CB5D4Ah
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 01693FCC5h
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 074B25FF4h
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 00ABA2FF1h
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 0B09231BFh
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 0079A848Bh
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 09A319AAFh
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 0B66CDF77h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 0F6A700EFh
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 00D814956h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 01904FB1Ah
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 01A394106h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 0EFDDD16Ch
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 005512406h
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 075CB4D46h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 03DAA0509h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 02CB80836h
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 0CBA5EC3Eh
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 036B3A4BCh
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 009A70C2Dh
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 0369A4D17h
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 0E121E24Fh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 018BE3C28h
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 0EC50B8DEh
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 03B967B3Dh
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 0B83B91A6h
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 02A98F7CCh
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 01F8FFB1Dh
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 03FA93D3Dh
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 032B3381Ch
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 06A583A81h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 01E2038BDh
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0030611A3h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 068B37000h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 05AC5645Eh
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 09602B592h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0E70F1F6Ch
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 0264639ECh
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 0C4592CC5h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 0920FB59Ch
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 00FB2919Eh
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 00C982C0Bh
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 0C7A72CDFh
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 002921C16h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 017B127EAh
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0AC3DA4AEh
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 0D44FD6DBh
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 02C911B3Ah
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 0AD19D0EAh
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 096B0913Bh
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 04BB626A8h
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 0E319B7C5h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 05F927806h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 077C5FEE7h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 07BDE4D76h
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 090BFA0F3h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0924491DFh
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 0FD6197B7h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 095B8ABF2h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 0EEBB8F76h
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 0F7CCB537h
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 0AC916FCBh
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 00E952C59h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 0BE05928Ah
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 084D362C7h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 0A0A0EE66h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 006D2298Fh
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 003911D39h
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 049C28E91h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 09B359EA3h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 06E35F61Fh
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 0042EDC04h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 0163F1CABh
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 0A23783AAh
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 070C34B44h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 0A4902D8Ah
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 09CAECE74h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 022BCCF36h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 0299D0C3Eh
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 08E319293h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 0491C78A6h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 060B16C32h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 020B10F6Ah
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 05AB65B38h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 0EB51ECC2h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 098D39446h
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 01BC3F6A9h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 0419F7230h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 034A21431h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 068B8741Ah
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 09136B2A1h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 070BB5E67h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 01CF8004Bh
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 011C3410Eh
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 080016B6Ah
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 0EB6BDED6h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 0D3B4D6C4h
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 072ED4142h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0B0207C61h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 0CDEFFD41h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 09F099D9Dh
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 0CF7DE7A1h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 06EB2EC62h
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 04CFC0A5Dh
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0348E382Ch
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 0B8AAB528h
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 085A95D9Dh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0AD325030h
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 00F9C1D01h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 0533D3DE8h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 0A6AF463Dh
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 0A6B5AA27h
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 0CD9D38FDh
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 018382487h
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 00B6410F3h
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 01A25FA79h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 0F2C103B9h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 031965B0Ah
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 0FAA72212h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 00386750Eh
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 028823A2Fh
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 0AB96218Bh
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 01B911D1Fh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 08A2290B6h
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 02581DD85h
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 002980237h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 08CAEC268h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 0FB53ECFBh
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 016B1CAE3h
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 0F2D21640h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 09706A793h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 016B85055h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 0C457E39Ch
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 037CBF2B6h
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 0036F07FDh
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 06C8F86C2h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 08725CE82h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 0923D7C34h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 079929A43h
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 072E8ACBEh
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 041146399h
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 0D14ED7D4h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 024B1D2A2h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 0999D8030h
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0D36EC9C1h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0151D1594h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 00AB43429h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 0745E2285h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 058942A5Ch
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 08F1B7843h
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 036A72F3Ah
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 082C1834Fh
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 07CDF2E69h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0D78BF51Dh
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 04A8B16B2h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 0188433DBh
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 066379875h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 032A03229h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 0F144D313h
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 00552E3C0h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 0873F6C6Bh
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 03FA60EF3h
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 016B73BE8h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 01A2F63DDh
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0C7350282h
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 099F2AF4Fh
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 03298E3D2h
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 005966B01h
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 09B1D5659h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 082400D68h
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 062B9740Eh
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 05DB24511h
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 09AAE3A6Ah
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 03E9BC0E9h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 0EB0AEA9Fh
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0C091CA00h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 0219FDE96h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 0203804A9h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 0DA4C1D1Ah
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 073816522h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 01A0E44C7h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0DCB3D223h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 0144F351Ch
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 04CD76C19h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 0009AF898h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 080953FB3h
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 01B2074B2h
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 00E088D1Eh
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 0B8299EB8h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 032A62A0Dh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0040B2499h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 034AD2036h
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 05B896703h
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0D19DFE2Dh
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 096288E47h
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 02EA1223Ch
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 0904BB1E6h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0B6AEC6BBh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 068A5287Eh
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 0D34D0411h
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 0B4AF2B95h
    call WhisperMain
RtlCreateUserThread ENDP

end