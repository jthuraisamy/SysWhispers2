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
    push 006A6516Bh
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 087BBED55h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 060EF5F4Ch
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 0FFEE60E6h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 09A47BA1Bh
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 00A992D4Ch
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 065238A66h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 022A4B696h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 0CC9A9AA9h
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 08854EAC5h
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 000920877h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 02EB30928h
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 06EF04328h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 02505ED21h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 00A900D0Ah
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 008904F4Bh
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 0CA991A35h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 0BB104907h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 001146E81h
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0219E447Ch
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 0CD41322Bh
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 033AB4571h
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 0859CB626h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 0C21CF5A7h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 07DDF6933h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 08210927Dh
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 0848A0545h
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 073D33167h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 03DFC5C06h
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 08510978Bh
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 03CEC0962h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 03CBE796Eh
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 0AF9E77B4h
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 02CB73522h
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 0CF52C3D7h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 03FEA3572h
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 07A402283h
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0EDBFCA2Fh
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 02968D802h
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 0FCDC0BB8h
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 0D9BFE5FEh
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 088918E05h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0B99AE54Eh
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 05B9F378Eh
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 0D747C3CAh
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 029881721h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 07CE73624h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 05AAA87EFh
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 0338E10D3h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 069FE4628h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0F919DDC5h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 036AC767Fh
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 0459DB5C9h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 03B6317B9h
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 0970A9398h
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 075DE5F42h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 068F9527Eh
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 006951810h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 02A972E00h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 01EDC7801h
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0A87B324Eh
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 072AF92FAh
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 047D37B57h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 008810914h
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 00547F3C3h
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 0251115B0h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 0A029D3E6h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 093B1138Dh
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 036AC3035h
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 00C540AC5h
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 028BC2D2Ah
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 028A7051Eh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 04EDF38CCh
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 008A00A0Dh
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 05CFABF7Ch
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 0FFB0192Ah
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 0E18CD336h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 00A90D729h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 06F9698C3h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 0CB903DDFh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 04A96004Fh
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 020B86211h
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 0ECCEE86Eh
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 05D2B67B6h
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 078B82A0Ch
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 0C88ACF00h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 00E80D2BEh
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 08837E8EBh
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 0D254D4C4h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0019B0111h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 009353989h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 018DC005Eh
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 00B4B4490h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 00A9B0877h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 08703B4BAh
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 039A23F32h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 0C78529DEh
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0B0292511h
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 006822A55h
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 034DA304Ch
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 08BA71195h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 038AC7100h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 0BD97F163h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 01D8C071Eh
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 047927D50h
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 00C996202h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 03BA57B73h
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 008A8F586h
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 022826A21h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 07521B787h
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 0A5BEB609h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 036AF3633h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 0A1A048DAh
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0EC573205h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 00EEFD8B1h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 064F25D58h
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 0D588D416h
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 026F15D1Eh
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 063EEBFBAh
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 050305BAEh
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 036D27407h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 00CA8E4FBh
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 032AB4151h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0F78AE40Dh
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0FAA01B33h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 0850687A8h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 034E4557Fh
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 036CE2D46h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 065B1E3ABh
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 020B21AFCh
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 064F4617Eh
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 04DE3063Ch
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 01E8A443Fh
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 04A5C2941h
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 0118B1414h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 0F68FDB2Eh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 020B14762h
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 01197F084h
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 027A82032h
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 07CC0458Dh
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 01B8F30D0h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 006BA3FE8h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 01882283Bh
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 06ABB720Ch
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 00B9BEF4Dh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 029AC4170h
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 0FEB58C6Ah
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 04F157E93h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 0CE48E0D5h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 0D0FA53CEh
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 079C07442h
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 0219C1131h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 0E35C1219h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 0C5A6D90Dh
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 0EE71FDFEh
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 0C80F266Fh
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 064F07D5Eh
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 009A0774Dh
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 0AC3FACA3h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 00CA42619h
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0ACBCEE06h
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 008C62584h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 018811F0Ah
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 000BDF8CBh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 043EF6178h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 08A10AA8Fh
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 0F8C7D448h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 00EA21C3Dh
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0924E0272h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 0F06AD23Ch
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 0145112E2h
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 026B9F48Eh
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0C2442229h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 022997A2Eh
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 05EB82864h
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 0FEA7DCF3h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 02EBD1DF2h
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 026885D0Fh
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 0E23BFBB7h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 0369BFCCAh
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 0CA50092Ah
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 003B03F1Ah
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 015813F3Ah
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 076985058h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 00AB6200Bh
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 057BB8BFFh
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 019DE6356h
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 04FC7CB11h
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 03D990530h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 0B8AAF67Ch
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 00413C643h
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 005B29396h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0772F97B2h
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 03D181D4Ch
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 01C77DE29h
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 0A514230Eh
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 0C899F62Ch
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 001DF6230h
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 0315E22B6h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0F22FADE4h
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 0EBB616C1h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 0C98135F6h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 09244C08Ch
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 0EB5F0535h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 036B73E2Ah
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 014B0D41Dh
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 086BBF741h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 0D28DF8C6h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 00CB7D3F7h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 0584904F1h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 0068E6E0Ah
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0FF03C0C9h
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 035A5C8FCh
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 0F0A400D8h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 0278FA994h
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0B14C0C69h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 016C72875h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 0F2EF9477h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 00CA40831h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 09BA0F53Ch
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 0169A6C78h
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 0698724B2h
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 003D5720Eh
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 0BF9B3985h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 0FB2180C1h
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 03EBC7A6Ch
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 081188797h
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0CD983AFCh
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 009BE2C2Eh
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 03F5329FDh
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 0079B2B0Dh
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 0735B09B6h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 00C4A00D7h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 01430D111h
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 01A87101Ah
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 08A9D2AA6h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 0768F782Eh
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 05E3E52A3h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 0D79D29F1h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 0B290EE20h
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 0E757EDCFh
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 0B207D8FBh
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 032FF1662h
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 005919C9Ah
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 072AA3003h
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 0C25592FEh
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 060D65368h
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0028E0601h
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0DB4C38DDh
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 00A80C7D2h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 01F8C5523h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 0DA32C7BCh
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 04C9F2584h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 083421171h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 0E0FEEF59h
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 0192E3B77h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 06E3743E8h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 0DA59E0E4h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 0B9742B43h
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 0F389F61Fh
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 0D461C7FAh
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 00D91191Dh
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 0CA949839h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 08AD579BAh
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 040AA2075h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 0C28E0839h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 0459D1E56h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 00564C018h
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 00DBB0738h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 00B963CD8h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 03E197EBEh
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 044A78CD8h
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 00E9AC8C5h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 022064DDAh
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 00D9F2D10h
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 017B82813h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 0103038A5h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 0548E7459h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 001980702h
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 07B95AFCAh
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0A8FB60D7h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 0C42D0677h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 02E8E3124h
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 0288A4F18h
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 008AE0E3Eh
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 072A21669h
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 028825B6Dh
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 087365F9Ch
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 04E800855h
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 03399071Ch
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 0469013A0h
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 0D44DF2DDh
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 084B0BC14h
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0F4A8F800h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 057942716h
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 01E45F059h
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 005339316h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0907C94D4h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 02CB80836h
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 0D6B9FF23h
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 0B42E80A4h
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 077D95E03h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 006B9190Bh
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 04A85BACAh
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 0D03ED4A8h
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 02EBBB080h
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 016974428h
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 08002F9ECh
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 0122575CAh
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 0F3F1E155h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 0DB8918DEh
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 01291E890h
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 07657248Ah
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 019A1EFDBh
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0A3818135h
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 0ACFC53A8h
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 094D79573h
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 0B322BAB9h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0FBD1B4FBh
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 069D30C25h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 00CB7F8E8h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 09F33BA9Bh
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 0AD33B19Ah
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 01B48C70Ah
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 019A1436Ah
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 018970400h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 065B76014h
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 02CBEC52Ch
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 08C9BEC09h
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 04EDE4376h
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 03D9CD0FEh
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 0E4BDE72Ah
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 0AF28BAA8h
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 009874730h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 0C15E3A30h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0EEBF946Fh
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 027923314h
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 09EB5A618h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0ACBFB522h
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 05EC86050h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 0183B6CFBh
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 0B3B0DA22h
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 05195B0EDh
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 02CDA5628h
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 01CF6E2B7h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 018BFFAFCh
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 0CC86EE52h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 08498D246h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 008922C47h
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 0F9AEFB3Fh
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 0FA9DD94Ah
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 076B810A2h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 01B2303A2h
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 00DAE7326h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 09687B413h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 060B00560h
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0305F23D8h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 0308C0C3Fh
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 07A91BDEEh
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 020DDCE8Ah
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 017AD0430h
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 02D96E6CCh
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 0992CFAF0h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 038BB0038h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 022B41AF8h
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 02235399Ah
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 0F89BE31Ch
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 064AB683Eh
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 06B4F0D50h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 04DDB4E44h
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 0178C371Eh
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 07AA6239Ah
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 016B0312Ah
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 014B67E73h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 0FE67DEF5h
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 09E3DBE8Fh
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 022FD1347h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 031BB6764h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 0E27CCBDFh
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 02CA10D7Ch
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 0292179E4h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 00F128301h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 014841A1Ah
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 0AE21AEBCh
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 0128F511Eh
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 0923D5C97h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 034CF46D6h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 024B02D2Eh
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0022B18AFh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0BD933DAFh
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 060495CC3h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 063B93B0Dh
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 017B62116h
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 0A232A2ABh
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 005CB328Ah
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 03A87AA8Bh
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 05FD57A7Fh
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 004BC3E31h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 02CF55107h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 0A3602878h
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 06AFD601Ch
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 03005ED36h
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 076A37037h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 002A39083h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 0C553EFC1h
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 0E4AEE222h
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 00C578470h
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 09649CAE3h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 040AA8FFDh
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 0B793C473h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 05D12BA4Bh
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 050D47049h
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 02AA61E30h
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 012027EF2h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 04ABAA932h
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 073893534h
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 01A4A3CDFh
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 036B9FC16h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 020EE2F45h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 016B40038h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 019429A8Fh
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 0765BD266h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 0228DCCD1h
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 09DA85118h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 0583D32FAh
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 00EAC032Ch
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0005FD37Fh
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 038AF263Ah
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 03A99AA95h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 0B51E4D73h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 08119473Bh
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0E8BDE11Bh
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 076E4A158h
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0A33DA0A2h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 0B885663Fh
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 07FAA0B7Dh
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0E129EFC3h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 064DC5E51h
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 08C979512h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 0F05EF4D3h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 03BAB0319h
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 04D164FFFh
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 0302EDD2Ah
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 0F4AACEFCh
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 0109B0810h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 0685111A1h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0C9399254h
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 05BF01D0Eh
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 034B33E13h
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 0C3952B06h
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 08695DA30h
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 03EEF276Ah
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 0E6B8328Eh
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 0099A2D09h
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 04DB6692Fh
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 0F2ADF320h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 05B3044A2h
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 00E924644h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 0A411AC8Fh
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 04D104387h
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 01C84C6CEh
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 003AEEBB2h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 0052D237Dh
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0CE93C407h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 05EC15855h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 00E0530A9h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 056D6B694h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 0FEAD01DBh
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 038650DDCh
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 0508E3B58h
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 03BA93B03h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 0F236FAADh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 01C17FD04h
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 03AA2D23Ah
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 00D962B4Dh
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 03D900EDEh
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 0E2462417h
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 015805550h
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 09A4FB3EEh
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 074CF7D6Bh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 07E4706A4h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 013CF4512h
    call WhisperMain
NtContinueEx ENDP

RtlCreateUserThread PROC
    push 07CE03635h
    call WhisperMain
RtlCreateUserThread ENDP

end