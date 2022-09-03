.686
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

NtAccessCheck PROC
    push 018A0737Dh
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 09BA97DB3h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 068B11B5Eh
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 07FEE1137h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 090BFA003h
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 01E941D38h
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 0EA79D8E0h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 07CF8ADCCh
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 059C9C8FDh
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 00E886E1Fh
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 044960E3Ah
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 05930A25Fh
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 02EBC2B22h
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 0340FF225h
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 008921512h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 04495DDA1h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 006286085h
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 093356B21h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 0720A7393h
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0DA9ADD04h
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 0322317BAh
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 011287BAFh
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 0A672CB80h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 0982089B9h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 0C1512DC6h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 0519E7C0Eh
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 03EAC1F7Bh
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0318CE8A7h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 0104523FEh
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 001930F05h
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 0396D26E6h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 0BB168A93h
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 08B9FF70Ch
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 020B04558h
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 079917101h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 0FB531910h
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 0144CD773h
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 0CE2CC5B1h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 02D7D51A9h
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 060C9AE95h
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 030971C08h
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 008E02671h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 0756F27B5h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 0C337DE9Eh
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 0D88FCC04h
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 005AC0D37h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 05A433EBEh
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 064B1500Ch
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 07BED8581h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 0761F6184h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0EA58F2EAh
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 01AB51B26h
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 0A8E240B0h
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 0228A241Fh
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 08B23AB8Eh
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0C99AF150h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 03895E81Ch
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 09B70CDAFh
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 016DB99C4h
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 02C050459h
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0A6B5C6B2h
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 07EA59CF0h
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 03191351Dh
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 0183371AEh
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 06DDD5958h
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 08350ADCCh
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 02EA07164h
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 055D63014h
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 03CA43609h
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 018B23A23h
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 03FB57C63h
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 011B0FFAAh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 03575CE31h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 0249304C1h
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 01D5C1AC4h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 034624AA3h
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 011B3E1CBh
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 0922FDC85h
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 0A8D15C80h
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 08792CB57h
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 01A8C5E27h
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 06AC0665Fh
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 02A0B34A9h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 02E83F03Ch
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 06756F762h
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 08000E5E6h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 0621E52D0h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 02A353AA9h
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 00C53C00Ch
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 051256B89h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 03C1704BBh
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 008B94C02h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 02EB52126h
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 06688641Dh
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 0E9392F67h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 0178326C0h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 01DC52886h
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 0DC56E104h
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 0C972F3DCh
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 0C55AC9C5h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 0C85426DFh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 01683D82Ah
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 041A9E191h
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 0458B7B2Ch
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 00F972544h
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 03D891114h
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 07FE55ABDh
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 01CB2020Bh
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 0380734AEh
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 009133583h
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 049AA1A9Dh
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 03C8415D9h
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 0FE65D1FFh
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0110A3997h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 06C973072h
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 010B1033Eh
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 061550348h
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 01E8F2520h
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 033AE7155h
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 0E1B28661h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 04ED3ADC1h
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 0FE6AE8DBh
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 042F6634Dh
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0FE67EBCEh
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0108A121Fh
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 038BCC8D7h
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 007AEFAC8h
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 0DA41CFE8h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 064F17F5Eh
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 03ABF3930h
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 0E073EFE8h
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0A1BEB813h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 01CBFD609h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 0349C283Fh
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 007BAC4E2h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 0D74AC2EBh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 026B63B3Eh
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 064C9605Bh
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0AF96D807h
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 00622F45Fh
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 01CBA4A67h
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 02037B507h
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 058BA8AE0h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 0397931E9h
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 0D794D342h
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0795C1FCEh
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 09EC04A8Eh
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 07B258F42h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 00AE60C77h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 03AAF0A0Dh
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 026471BD0h
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 049D54157h
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 068C56852h
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 00D94050Fh
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 030B2196Ch
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 0D0A8E717h
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 03EB03B22h
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 03795DD89h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 07AE3022Fh
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 03AA4760Bh
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 042AEB0D4h
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 05A1F9944h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 079DC023Bh
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 034944A63h
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 0039635D2h
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 09C929232h
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 02D6903F3h
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 0F3CEDF11h
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 054BC1602h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 069329245h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 067D8535Ah
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 02EBDB48Ah
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0BE119B48h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 096197812h
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 074B2026Eh
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 014825455h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 01CB1E5DCh
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 04E908625h
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 05FDE4E52h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 000DAF080h
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 0805BB2E1h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 01E8E381Bh
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 0103302B8h
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 01D0FC3B4h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 09A26E8CBh
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 054AA9BDDh
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 0144622FFh
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 0EB52365Dh
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 020482AD1h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 08A99CC66h
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 0168C3411h
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 0B22E98B3h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 065392CE4h
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 0393C3BA2h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 020BD2726h
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 01CBECF89h
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 02AA91E26h
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 08E248FABh
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 096119E7Ch
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 0D27FF1E0h
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 0C99D3CE3h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 0DF9315D0h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 0E278ECDCh
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 01FAB3208h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 01897120Ah
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 01EB55799h
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 0A79A9224h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 076BC4014h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 00CC22507h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 0F82FF685h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 01E8E2A1Eh
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 0D24BD7C2h
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 09DCEAD19h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 04C914109h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 034844D6Fh
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 07FD24267h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 06AB56A29h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 038A81E21h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 03A92D781h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 0E55CD3D8h
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 00484F1F9h
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 00B9845AEh
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 0F557C2CEh
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 0693F9567h
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 0D461E3DFh
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 07EBC7E2Ch
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 0B31C89AFh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 06BC0429Bh
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 011BC2A12h
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 026452CC5h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 013CB00ADh
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 0B28BB815h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 044CB0A13h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 06B4E279Eh
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 006937878h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 084EAA254h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 0B49BA434h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 084B7B211h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 01B9E1E0Eh
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 0EE4B2CEDh
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 02B12C80Eh
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 0823CAA87h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 0105E2CDAh
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 04550AA4Ah
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 0B000BAAEh
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 02C93C098h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 06CECA3B6h
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0BC533055h
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 0CB578F84h
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 00440C162h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 027AA3515h
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 0E173E0FDh
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 012B81A26h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 0849AD429h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 0ECA229FEh
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 0083A69A3h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 0AB3221EEh
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 07399B624h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 03A3D365Ah
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 04F3248A0h
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 0DEABF13Dh
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 00794EEFBh
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 0A13ECFE4h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 01E3D74A2h
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 00AE16A33h
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 0169B1AFCh
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 029B5721Eh
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 0365CF80Ah
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 0099AFCE1h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 021C8CD98h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 0AA3A816Eh
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 08B54FFA8h
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 0F1FBD3A0h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 065BE7236h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 001890314h
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 05BD55E63h
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 020944861h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 07067F071h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 0F341013Fh
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 00F99C3DCh
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0104416DEh
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 0889ABA21h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 0E87FEBE8h
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 0B22DF5FEh
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 02AAD0E7Ch
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 0108DD0DFh
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 0785F07BDh
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 0E75BFBEAh
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 09CC47B51h
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 0F9512419h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 09306CBBBh
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 0D2053455h
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 00A943819h
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0183F5496h
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 00B189804h
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 09C089C9Bh
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 005E791C6h
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0C6693A38h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 0089003FEh
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 0F9A71DCCh
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 004D057EEh
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 0D9469E8Dh
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 028950FC5h
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 0E12EDD61h
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 012B41622h
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 00E913E3Ah
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 04ED9AF84h
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 0000A1B9Dh
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 0EAD9F64Ch
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 0F7EEFB75h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 0178D1F1Bh
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 074CA7E6Ah
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 0C8530A69h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 0E65ACF07h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 013461DDBh
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 0E4A4944Fh
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 0C6CDC662h
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 09B07BA93h
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 0A80AAF91h
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 02FB12E23h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 007A5C2EBh
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 0A73AA8A9h
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 007B6EEEEh
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 002ED227Fh
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 0B32C9DB0h
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 0CC9A2E03h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 04FC9365Ah
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0D73B26AFh
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 05ED55E47h
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 0D4433CCCh
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 0825AF1A0h
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 0DE19F380h
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 00DB3606Ah
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 061DAB182h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 069306CA8h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 0E2B83781h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 07D27A48Ch
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 013BCE0C3h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 005AAE1D7h
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 03AAA6416h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 01702E100h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 0CA9129DAh
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 0534A0796h
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 09694C44Eh
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 0C24DE4D9h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 0A3039595h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 0FAEB18E7h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 0FCACFE16h
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 03F6E1A3Dh
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 0CF5CD1CDh
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 09236B7A4h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 0C8530818h
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 0605F52FCh
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 006379837h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 0049326C7h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 0EE76DE3Ah
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0DB88FCD3h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 03E9FE8BBh
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 06496A2E8h
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 0CA5FCBF4h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 0E9DF04ACh
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 005B75116h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 0DD58FCC2h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 0AEAF5BD5h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 0E47EE1EEh
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 0E073F9F6h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 0DC313C62h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 012DF2E5Ah
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 02BFE4615h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 083D37ABEh
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 00895C8C7h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 054B85056h
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 0D9469E8Dh
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 010B7F7E2h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 003D73B7Ah
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 00D339D2Dh
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 077CB5654h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 01790EBE4h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 025A32A3Ch
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 0128D0102h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 097421756h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 0B16B8BC3h
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 007990D1Dh
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 022BB2406h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 02499AD4Eh
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 0268C2825h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0D749D8EDh
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 0FB72E0FDh
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 0BC24BA98h
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 0A40A192Fh
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 0B7998D35h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 0BD2A4348h
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 044CC405Dh
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 050D47445h
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 0FF5D1906h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 01C21E44Dh
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 0C054E1C2h
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 08FA0B52Eh
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 0D859E5FDh
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 0E3C7FF6Ah
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 06EF76E62h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 08D088394h
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 0174BCAE0h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 001B56948h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 019901D1Fh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 084509CCEh
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 0EC263464h
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 0C030E6A5h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 02695F9C2h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 08CA4FF44h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 011923702h
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 004DC004Dh
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 09E3DA8AEh
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 0D847888Bh
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 01E88F888h
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 01C0124BEh
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 0D9B6DF25h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 0D950A7D2h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 03EAB4F3Fh
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 08204E480h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 09BD89B16h
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 0B54085F8h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 054C27455h
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 07458C176h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 01EBFD488h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 01288F19Eh
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0CCEDF547h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 0C452D8B7h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 0A63B9E97h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 0223C44CFh
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 0815AD3EFh
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 0049DCAB8h
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 09E39D3E0h
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0315E32C0h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 036932821h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0019FF3D9h
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 060BF7434h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 0049F5245h
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 0CF52DAF3h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 0C2A133E8h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 077E74B55h
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 03FA9F9F3h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 0FF56FCCDh
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 08F159CA1h
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 0DD6A2061h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 068BD075Bh
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 033D56F58h
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 029E71F58h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 02A7B5CEFh
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 0FFA8C917h
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 04A914E2Ch
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 0EA3FB7FEh
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 0CD02DFB3h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 08B9012A6h
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 046BA6C7Dh
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 000CF1D66h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 090CA6AADh
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 0F8AED47Bh
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 0D34FC1D0h
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 0B4165C0Bh
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 06AD32A5Ch
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 0F7BC10D7h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 0C089E259h
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0F56929C7h
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 0D843FA97h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 09813DAC7h
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 088DA86B3h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 0B053F2E9h
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 0FE3CC196h
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 000902D08h
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 08525A983h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 0905B92CFh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0900BD6DBh
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 08E15828Eh
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 0DC8FDA1Ch
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0031E49A0h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 08117868Ch
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 0359314C2h
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 09801A1BCh
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0B9A357A9h
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 0A0BF2EA8h
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 05FC5BBB9h
    call WhisperMain
NtContinueEx ENDP

end