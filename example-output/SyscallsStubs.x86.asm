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
    push 0B6D641BBh
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 0163E3285h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 02EB72D38h
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 0D19E1AC6h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 018A02BEFh
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 0829013BEh
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 028C05C56h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 0D841A2A6h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 0C9719FCBh
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 016801617h
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 01457341Ah
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 07AB26F32h
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 0DA342B5Ah
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 02A8E6857h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 0CB020C49h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 046D16D51h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 01F3075CEh
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 085115D55h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 02490F9CAh
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 019CD7426h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 038AD2144h
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 0C221CCB2h
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 03BE15A1Ah
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 01C1D1F87h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 03191457Dh
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 0832D80A2h
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 0C85C2D8Bh
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0379E6D37h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 039002E90h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 001990F0Fh
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 058F16D58h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 0BF1C984Fh
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 0939DD948h
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 038B1235Eh
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 033AE1F39h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 01DA027ECh
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 0B207F4A5h
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0EAA8F120h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 0725AB909h
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 022CC205Dh
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 0DABDE4F0h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 0D28DF657h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0AF8072D4h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 077BF5E26h
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 022B3ADB4h
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 0058C0D17h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 0BA4FC4B9h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 038AA7A50h
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 02B89C793h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 07ECF5E94h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0E77EEFEBh
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 0C20DE25Fh
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 03F38BD21h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 0EFB51AD7h
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 0DFB2FB39h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 03C16F04Ch
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 0C94297F7h
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 00B970317h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 010BFECF0h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 008B62A2Bh
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 09DDBBC81h
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 0704ABB1Ch
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 001910F07h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 0004D07C6h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 09449F4DBh
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 00B9EFF06h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0D55BEACFh
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 09233B5AFh
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 036822C3Bh
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 060CA061Fh
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 0964EF75Ch
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 000BD7B4Ah
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 064C05C66h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 03E911CDDh
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 07CAB2E9Eh
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 00FD80B43h
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 08F8FCD34h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 076D96C6Fh
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 029933921h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 099F38567h
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 0E04BE6DFh
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 094AD1E8Bh
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 050800A31h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 0C608DEB2h
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 0D87CA29Ch
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 031746CDCh
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 036BA0E24h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 00BAB657Ah
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 05B357D66h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0F75ADF07h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 004985645h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 0B8BB5EBFh
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 042864312h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 0ED4BEBD8h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 02AFC0D63h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 08B9FFB1Dh
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 09CA9F453h
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0B72E5D20h
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 050C2100Fh
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 01ABC1024h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 0C04DF8DEh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 07ACB6B7Eh
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 0E1132F46h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 049947D28h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 047D2736Eh
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 01F988590h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 03D973D01h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 05CCEDEEFh
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 020985A45h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 09CA377E5h
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 0378A9940h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 0391729BBh
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 05FBE7024h
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 04E575ECBh
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 076EFA8B9h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 0ACF19342h
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 08DDE9967h
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 0A0BE1DB0h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 03D0F71CBh
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 022B33D38h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 006AA263Fh
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 01A9E1E7Fh
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 0D048B9D7h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 056C94B58h
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 036AD10F9h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 0F761E7CAh
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 0049C293Bh
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 09CC79146h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 0593058BEh
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 0FE760D38h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 0A93184AFh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0C557C6C8h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 09427D601h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 03CAE4643h
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 093B15C90h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 0772A826Bh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 0E1720463h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 000A80239h
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 09734447Ch
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 01C800A1Dh
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 0098D2332h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 01AAC6E46h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 0D8052A7Fh
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 038AFEC1Ch
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 096143ACAh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0BB9CC350h
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 0AA35FCFEh
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 0D76AECDDh
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 00F980302h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 0B329F1F8h
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 0C3A5FE0Bh
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 0039D0313h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 0D043D6D8h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 043C3495Bh
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 020B52F36h
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 098CAA368h
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 066BF195Ch
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 02B97BF95h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 00CA1645Dh
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 009A1FFDBh
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0F6790F3Fh
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 016300A8Ah
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 06BA72A6Dh
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 00757F637h
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 07B996D02h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 052C8725Fh
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 096BDAE11h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 082C28450h
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0ECA3351Eh
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 0E05DDBFAh
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 015349407h
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 0E97ED3D9h
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 07E9E1C88h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 085031D03h
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 06AFA5BAEh
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 036AC163Bh
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 0DC4EBFD0h
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 096B2AD2Dh
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 0272D24A2h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 0F4DDEB67h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 005BBD0E7h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 09F87DF55h
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 0BB62C3A8h
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 0109BF8D6h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 00B24F92Ah
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 098B757F1h
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 09CB7962Ch
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 0B02BEFA6h
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 084AD920Eh
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 020A25258h
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 0E237DA9Dh
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 019A136F0h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0EDA3CE3Fh
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0073D77C1h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 02871CA1Fh
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0B4BA5BB1h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 0DCCDF265h
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 07E3197ADh
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 058D98B96h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0AD5F2C4Dh
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 00D951502h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 0CA96DE0Bh
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 014B3DE16h
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 069D34464h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 074DA8FD6h
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 01CAD3F35h
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 0C51D1046h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 0134B3F87h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 08A8D871Dh
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 015CB8BF0h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 068909F00h
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0D34AD0DDh
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 06BF90732h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 00E963B09h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 02C96B699h
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0D19DE521h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 00C90361Dh
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 0128A3019h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 00EA60E33h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 0C355ADCAh
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 0769F2A4Ah
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 0A634616Ah
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 00FD14672h
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 04D9BB1DBh
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 019CEE8B6h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 079399F6Ah
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 03FA90907h
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0802BDAE2h
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 07BE16462h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 00E6A100Fh
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 00F4A05DDh
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 0969A1DA4h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 04C922453h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 054D01671h
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 09A3B8A99h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 086A2C25Eh
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 036893E26h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 0FC74C8F1h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 0863B9757h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 08A895136h
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 02292AB8Dh
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 00F3F1194h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 0B779F9CFh
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 00794898Ch
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 081A8C174h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 0883AB77Eh
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 0FEDEC97Ah
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0198AF1DAh
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 008922A07h
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 022BA5568h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 07BA27317h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 020B3CF28h
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 0945DFE86h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 06342B777h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 090AEA036h
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 069209848h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 02149CB54h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 063681596h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 02D74AB69h
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 022C03565h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 07621558Eh
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 019916919h
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 022BC2C21h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 006984055h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 019743BA5h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 03EF510A6h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 02F9E5E62h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 002917268h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 0B9F575A0h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 019820116h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 0EED4AFF2h
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 0C92793F2h
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 028142F8Bh
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 023B92826h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 0018EEF92h
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 089D34C85h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 010B3DCEDh
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 036A9163Bh
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 008B4D919h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 04D5A9906h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0B55EF5E3h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 026BD7460h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 046CC615Eh
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 0E8B7F13Ah
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 0DB5ADFCDh
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 0CE912CC5h
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 0AA8EB728h
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 0B3ED8D40h
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 01572C81Dh
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 0C71FEFA6h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 0709E5A5Eh
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 0DA909A42h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 00C91040Dh
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0EECCF26Fh
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 08D249BC0h
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
    push 08E108A88h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 0054071ACh
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 0CB55CEC3h
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 038B6D025h
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 030274DD5h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 0C25DF1C1h
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 09334726Bh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 01AA5F2FAh
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 015343DF4h
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 019B69D96h
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 030AC153Ch
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 078CC82CDh
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 06C3178D0h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 04C1B6285h
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 076CF1C40h
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 00A1946ADh
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 0EC48C0F3h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 00B2E75C3h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 038987C42h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 0B0BA5EB2h
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 051C3B257h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0FADDD389h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 00395320Fh
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 004B82DE5h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 09932B2ADh
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 0EBD3B9F3h
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 01ED41C79h
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 035B76176h
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 0254E0FECh
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 0CF5CF80Ch
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0A061F6DCh
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 01BB51EDEh
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 03A3F29B4h
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 0ED24D096h
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 07E965F42h
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 08294ED4Eh
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 077DBA48Fh
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 019B4241Ch
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0BCBBB61Fh
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 0FC66E4CDh
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 0EFBD8563h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0045FF92Bh
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 0CD5F32C5h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 0132B3377h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 04CBB7764h
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 023DEEF9Ah
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 0697D29B5h
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 01E816402h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 0AC0E8282h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 09A4BFC9Fh
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 098B9269Eh
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 001A8217Ah
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 009978393h
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 0EEA1CF33h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 011933405h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 04D905F0Ch
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 082B5B60Fh
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 0D54EF51Ch
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 066F67F62h
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 008890F12h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 0BC8D8A29h
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 0B49732A8h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 01050FE46h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 01B0C46D8h
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 02FA9E7F0h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 066CE7554h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 022BE3E1Eh
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 024B42B2Eh
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 0A0374F24h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 044CE8F88h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 0FCE9375Ah
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 0FB3EE7A5h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 011A90C20h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 0C629C4C5h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 059204DCCh
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 031872C15h
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 0CA51CAC3h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 09CBDDA69h
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 003AF9F82h
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 03BAF2A30h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 09798D324h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 067827A6Ch
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 0983281BCh
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0CBD8D946h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 0960E8E84h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 0779C2F4Bh
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 0AABA3194h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 03E10D901h
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 0AB9BA70Bh
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0B3316903h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 0A734A0BFh
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0452D7FEBh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0299B6E3Ah
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 013A51131h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 0C0FA48C8h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 0D753F5CCh
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 03F6ECE0Dh
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 00850DB12h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 08837B8BBh
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 0479B3A4Dh
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 08ED07ACFh
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 0C2785060h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 0C41FD0BDh
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 0A8A67607h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 063D6755Eh
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 01681381Dh
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 005349715h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 09B028F9Fh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 0786D108Fh
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 076A1B0F8h
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 002D843F7h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 0C92F0C73h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 05B6A2499h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 040D27C5Bh
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 0A43DA4A3h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 0A23B5420h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 0FAD676B9h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 01C9F0B0Ch
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 00F935D4Eh
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 0072F4385h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 010892602h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 03EAD353Dh
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 012B3ECA8h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 0CF356FABh
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 01CFA2E40h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 054CE745Dh
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 01DCF5F12h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 03402BB21h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 016CB77DEh
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0C0ECECB7h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0189320D4h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 029111FA8h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 0249E3611h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 060356B93h
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0E5B21DE6h
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 006A77F3Ah
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 077AB5232h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 01CBD5E1Bh
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0BDAC5CBAh
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0613E59E2h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 01EA037FDh
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 08CAFE33Ch
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 03EAC3439h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 0900AF0DEh
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 0B865DEF4h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 0F2B2CFE7h
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 009B78290h
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 09CD7A65Bh
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 05B2C58B5h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0EE7706E9h
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 03F99C3E2h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 0E1781BFFh
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 00F98213Fh
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 040DA1604h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 0209C6524h
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 00C851638h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 01BC3E185h
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 06CABA912h
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 0968A759Ch
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 0F918FC89h
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0489E7A52h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 023332BA4h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 072DF924Dh
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 00B4D01D4h
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 0D421DCA5h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 09E05BE8Bh
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0FD69C1A2h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 01C47DE17h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 01C844249h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 01A90361Ah
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 0984DC69Bh
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 0C951D0DFh
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 0E0452617h
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 0ECB6E62Ch
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 07ADD647Dh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 07D557FF9h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 05A6F42F8h
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 00D992ACBh
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0C38E50AFh
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 06DAF4A7Ch
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 05517B042h
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 0043EE142h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0EAAEF31Bh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 0F0D1E66Eh
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 02794F0CBh
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 016AE441Fh
    call WhisperMain
RtlCreateUserThread ENDP

end