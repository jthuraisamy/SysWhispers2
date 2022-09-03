[SECTION .data]
currentHash:    dd  0

[SECTION .text]

BITS 64
DEFAULT REL

global NtAccessCheck
global NtWorkerFactoryWorkerReady
global NtAcceptConnectPort
global NtMapUserPhysicalPagesScatter
global NtWaitForSingleObject
global NtCallbackReturn
global NtReadFile
global NtDeviceIoControlFile
global NtWriteFile
global NtRemoveIoCompletion
global NtReleaseSemaphore
global NtReplyWaitReceivePort
global NtReplyPort
global NtSetInformationThread
global NtSetEvent
global NtClose
global NtQueryObject
global NtQueryInformationFile
global NtOpenKey
global NtEnumerateValueKey
global NtFindAtom
global NtQueryDefaultLocale
global NtQueryKey
global NtQueryValueKey
global NtAllocateVirtualMemory
global NtQueryInformationProcess
global NtWaitForMultipleObjects32
global NtWriteFileGather
global NtCreateKey
global NtFreeVirtualMemory
global NtImpersonateClientOfPort
global NtReleaseMutant
global NtQueryInformationToken
global NtRequestWaitReplyPort
global NtQueryVirtualMemory
global NtOpenThreadToken
global NtQueryInformationThread
global NtOpenProcess
global NtSetInformationFile
global NtMapViewOfSection
global NtAccessCheckAndAuditAlarm
global NtUnmapViewOfSection
global NtReplyWaitReceivePortEx
global NtTerminateProcess
global NtSetEventBoostPriority
global NtReadFileScatter
global NtOpenThreadTokenEx
global NtOpenProcessTokenEx
global NtQueryPerformanceCounter
global NtEnumerateKey
global NtOpenFile
global NtDelayExecution
global NtQueryDirectoryFile
global NtQuerySystemInformation
global NtOpenSection
global NtQueryTimer
global NtFsControlFile
global NtWriteVirtualMemory
global NtCloseObjectAuditAlarm
global NtDuplicateObject
global NtQueryAttributesFile
global NtClearEvent
global NtReadVirtualMemory
global NtOpenEvent
global NtAdjustPrivilegesToken
global NtDuplicateToken
global NtContinue
global NtQueryDefaultUILanguage
global NtQueueApcThread
global NtYieldExecution
global NtAddAtom
global NtCreateEvent
global NtQueryVolumeInformationFile
global NtCreateSection
global NtFlushBuffersFile
global NtApphelpCacheControl
global NtCreateProcessEx
global NtCreateThread
global NtIsProcessInJob
global NtProtectVirtualMemory
global NtQuerySection
global NtResumeThread
global NtTerminateThread
global NtReadRequestData
global NtCreateFile
global NtQueryEvent
global NtWriteRequestData
global NtOpenDirectoryObject
global NtAccessCheckByTypeAndAuditAlarm
global NtWaitForMultipleObjects
global NtSetInformationObject
global NtCancelIoFile
global NtTraceEvent
global NtPowerInformation
global NtSetValueKey
global NtCancelTimer
global NtSetTimer
global NtAccessCheckByType
global NtAccessCheckByTypeResultList
global NtAccessCheckByTypeResultListAndAuditAlarm
global NtAccessCheckByTypeResultListAndAuditAlarmByHandle
global NtAcquireProcessActivityReference
global NtAddAtomEx
global NtAddBootEntry
global NtAddDriverEntry
global NtAdjustGroupsToken
global NtAdjustTokenClaimsAndDeviceGroups
global NtAlertResumeThread
global NtAlertThread
global NtAlertThreadByThreadId
global NtAllocateLocallyUniqueId
global NtAllocateReserveObject
global NtAllocateUserPhysicalPages
global NtAllocateUuids
global NtAllocateVirtualMemoryEx
global NtAlpcAcceptConnectPort
global NtAlpcCancelMessage
global NtAlpcConnectPort
global NtAlpcConnectPortEx
global NtAlpcCreatePort
global NtAlpcCreatePortSection
global NtAlpcCreateResourceReserve
global NtAlpcCreateSectionView
global NtAlpcCreateSecurityContext
global NtAlpcDeletePortSection
global NtAlpcDeleteResourceReserve
global NtAlpcDeleteSectionView
global NtAlpcDeleteSecurityContext
global NtAlpcDisconnectPort
global NtAlpcImpersonateClientContainerOfPort
global NtAlpcImpersonateClientOfPort
global NtAlpcOpenSenderProcess
global NtAlpcOpenSenderThread
global NtAlpcQueryInformation
global NtAlpcQueryInformationMessage
global NtAlpcRevokeSecurityContext
global NtAlpcSendWaitReceivePort
global NtAlpcSetInformation
global NtAreMappedFilesTheSame
global NtAssignProcessToJobObject
global NtAssociateWaitCompletionPacket
global NtCallEnclave
global NtCancelIoFileEx
global NtCancelSynchronousIoFile
global NtCancelTimer2
global NtCancelWaitCompletionPacket
global NtCommitComplete
global NtCommitEnlistment
global NtCommitRegistryTransaction
global NtCommitTransaction
global NtCompactKeys
global NtCompareObjects
global NtCompareSigningLevels
global NtCompareTokens
global NtCompleteConnectPort
global NtCompressKey
global NtConnectPort
global NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
global NtCreateDebugObject
global NtCreateDirectoryObject
global NtCreateDirectoryObjectEx
global NtCreateEnclave
global NtCreateEnlistment
global NtCreateEventPair
global NtCreateIRTimer
global NtCreateIoCompletion
global NtCreateJobObject
global NtCreateJobSet
global NtCreateKeyTransacted
global NtCreateKeyedEvent
global NtCreateLowBoxToken
global NtCreateMailslotFile
global NtCreateMutant
global NtCreateNamedPipeFile
global NtCreatePagingFile
global NtCreatePartition
global NtCreatePort
global NtCreatePrivateNamespace
global NtCreateProcess
global NtCreateProfile
global NtCreateProfileEx
global NtCreateRegistryTransaction
global NtCreateResourceManager
global NtCreateSemaphore
global NtCreateSymbolicLinkObject
global NtCreateThreadEx
global NtCreateTimer
global NtCreateTimer2
global NtCreateToken
global NtCreateTokenEx
global NtCreateTransaction
global NtCreateTransactionManager
global NtCreateUserProcess
global NtCreateWaitCompletionPacket
global NtCreateWaitablePort
global NtCreateWnfStateName
global NtCreateWorkerFactory
global NtDebugActiveProcess
global NtDebugContinue
global NtDeleteAtom
global NtDeleteBootEntry
global NtDeleteDriverEntry
global NtDeleteFile
global NtDeleteKey
global NtDeleteObjectAuditAlarm
global NtDeletePrivateNamespace
global NtDeleteValueKey
global NtDeleteWnfStateData
global NtDeleteWnfStateName
global NtDisableLastKnownGood
global NtDisplayString
global NtDrawText
global NtEnableLastKnownGood
global NtEnumerateBootEntries
global NtEnumerateDriverEntries
global NtEnumerateSystemEnvironmentValuesEx
global NtEnumerateTransactionObject
global NtExtendSection
global NtFilterBootOption
global NtFilterToken
global NtFilterTokenEx
global NtFlushBuffersFileEx
global NtFlushInstallUILanguage
global NtFlushInstructionCache
global NtFlushKey
global NtFlushProcessWriteBuffers
global NtFlushVirtualMemory
global NtFlushWriteBuffer
global NtFreeUserPhysicalPages
global NtFreezeRegistry
global NtFreezeTransactions
global NtGetCachedSigningLevel
global NtGetCompleteWnfStateSubscription
global NtGetContextThread
global NtGetCurrentProcessorNumber
global NtGetCurrentProcessorNumberEx
global NtGetDevicePowerState
global NtGetMUIRegistryInfo
global NtGetNextProcess
global NtGetNextThread
global NtGetNlsSectionPtr
global NtGetNotificationResourceManager
global NtGetWriteWatch
global NtImpersonateAnonymousToken
global NtImpersonateThread
global NtInitializeEnclave
global NtInitializeNlsFiles
global NtInitializeRegistry
global NtInitiatePowerAction
global NtIsSystemResumeAutomatic
global NtIsUILanguageComitted
global NtListenPort
global NtLoadDriver
global NtLoadEnclaveData
global NtLoadHotPatch
global NtLoadKey
global NtLoadKey2
global NtLoadKeyEx
global NtLockFile
global NtLockProductActivationKeys
global NtLockRegistryKey
global NtLockVirtualMemory
global NtMakePermanentObject
global NtMakeTemporaryObject
global NtManagePartition
global NtMapCMFModule
global NtMapUserPhysicalPages
global NtMapViewOfSectionEx
global NtModifyBootEntry
global NtModifyDriverEntry
global NtNotifyChangeDirectoryFile
global NtNotifyChangeDirectoryFileEx
global NtNotifyChangeKey
global NtNotifyChangeMultipleKeys
global NtNotifyChangeSession
global NtOpenEnlistment
global NtOpenEventPair
global NtOpenIoCompletion
global NtOpenJobObject
global NtOpenKeyEx
global NtOpenKeyTransacted
global NtOpenKeyTransactedEx
global NtOpenKeyedEvent
global NtOpenMutant
global NtOpenObjectAuditAlarm
global NtOpenPartition
global NtOpenPrivateNamespace
global NtOpenProcessToken
global NtOpenRegistryTransaction
global NtOpenResourceManager
global NtOpenSemaphore
global NtOpenSession
global NtOpenSymbolicLinkObject
global NtOpenThread
global NtOpenTimer
global NtOpenTransaction
global NtOpenTransactionManager
global NtPlugPlayControl
global NtPrePrepareComplete
global NtPrePrepareEnlistment
global NtPrepareComplete
global NtPrepareEnlistment
global NtPrivilegeCheck
global NtPrivilegeObjectAuditAlarm
global NtPrivilegedServiceAuditAlarm
global NtPropagationComplete
global NtPropagationFailed
global NtPulseEvent
global NtQueryAuxiliaryCounterFrequency
global NtQueryBootEntryOrder
global NtQueryBootOptions
global NtQueryDebugFilterState
global NtQueryDirectoryFileEx
global NtQueryDirectoryObject
global NtQueryDriverEntryOrder
global NtQueryEaFile
global NtQueryFullAttributesFile
global NtQueryInformationAtom
global NtQueryInformationByName
global NtQueryInformationEnlistment
global NtQueryInformationJobObject
global NtQueryInformationPort
global NtQueryInformationResourceManager
global NtQueryInformationTransaction
global NtQueryInformationTransactionManager
global NtQueryInformationWorkerFactory
global NtQueryInstallUILanguage
global NtQueryIntervalProfile
global NtQueryIoCompletion
global NtQueryLicenseValue
global NtQueryMultipleValueKey
global NtQueryMutant
global NtQueryOpenSubKeys
global NtQueryOpenSubKeysEx
global NtQueryPortInformationProcess
global NtQueryQuotaInformationFile
global NtQuerySecurityAttributesToken
global NtQuerySecurityObject
global NtQuerySecurityPolicy
global NtQuerySemaphore
global NtQuerySymbolicLinkObject
global NtQuerySystemEnvironmentValue
global NtQuerySystemEnvironmentValueEx
global NtQuerySystemInformationEx
global NtQueryTimerResolution
global NtQueryWnfStateData
global NtQueryWnfStateNameInformation
global NtQueueApcThreadEx
global NtRaiseException
global NtRaiseHardError
global NtReadOnlyEnlistment
global NtRecoverEnlistment
global NtRecoverResourceManager
global NtRecoverTransactionManager
global NtRegisterProtocolAddressInformation
global NtRegisterThreadTerminatePort
global NtReleaseKeyedEvent
global NtReleaseWorkerFactoryWorker
global NtRemoveIoCompletionEx
global NtRemoveProcessDebug
global NtRenameKey
global NtRenameTransactionManager
global NtReplaceKey
global NtReplacePartitionUnit
global NtReplyWaitReplyPort
global NtRequestPort
global NtResetEvent
global NtResetWriteWatch
global NtRestoreKey
global NtResumeProcess
global NtRevertContainerImpersonation
global NtRollbackComplete
global NtRollbackEnlistment
global NtRollbackRegistryTransaction
global NtRollbackTransaction
global NtRollforwardTransactionManager
global NtSaveKey
global NtSaveKeyEx
global NtSaveMergedKeys
global NtSecureConnectPort
global NtSerializeBoot
global NtSetBootEntryOrder
global NtSetBootOptions
global NtSetCachedSigningLevel
global NtSetCachedSigningLevel2
global NtSetContextThread
global NtSetDebugFilterState
global NtSetDefaultHardErrorPort
global NtSetDefaultLocale
global NtSetDefaultUILanguage
global NtSetDriverEntryOrder
global NtSetEaFile
global NtSetHighEventPair
global NtSetHighWaitLowEventPair
global NtSetIRTimer
global NtSetInformationDebugObject
global NtSetInformationEnlistment
global NtSetInformationJobObject
global NtSetInformationKey
global NtSetInformationResourceManager
global NtSetInformationSymbolicLink
global NtSetInformationToken
global NtSetInformationTransaction
global NtSetInformationTransactionManager
global NtSetInformationVirtualMemory
global NtSetInformationWorkerFactory
global NtSetIntervalProfile
global NtSetIoCompletion
global NtSetIoCompletionEx
global NtSetLdtEntries
global NtSetLowEventPair
global NtSetLowWaitHighEventPair
global NtSetQuotaInformationFile
global NtSetSecurityObject
global NtSetSystemEnvironmentValue
global NtSetSystemEnvironmentValueEx
global NtSetSystemInformation
global NtSetSystemPowerState
global NtSetSystemTime
global NtSetThreadExecutionState
global NtSetTimer2
global NtSetTimerEx
global NtSetTimerResolution
global NtSetUuidSeed
global NtSetVolumeInformationFile
global NtSetWnfProcessNotificationEvent
global NtShutdownSystem
global NtShutdownWorkerFactory
global NtSignalAndWaitForSingleObject
global NtSinglePhaseReject
global NtStartProfile
global NtStopProfile
global NtSubscribeWnfStateChange
global NtSuspendProcess
global NtSuspendThread
global NtSystemDebugControl
global NtTerminateEnclave
global NtTerminateJobObject
global NtTestAlert
global NtThawRegistry
global NtThawTransactions
global NtTraceControl
global NtTranslateFilePath
global NtUmsThreadYield
global NtUnloadDriver
global NtUnloadKey
global NtUnloadKey2
global NtUnloadKeyEx
global NtUnlockFile
global NtUnlockVirtualMemory
global NtUnmapViewOfSectionEx
global NtUnsubscribeWnfStateChange
global NtUpdateWnfStateData
global NtVdmControl
global NtWaitForAlertByThreadId
global NtWaitForDebugEvent
global NtWaitForKeyedEvent
global NtWaitForWorkViaWorkerFactory
global NtWaitHighEventPair
global NtWaitLowEventPair
global NtAcquireCMFViewOwnership
global NtCancelDeviceWakeupRequest
global NtClearAllSavepointsTransaction
global NtClearSavepointTransaction
global NtRollbackSavepointTransaction
global NtSavepointTransaction
global NtSavepointComplete
global NtCreateSectionEx
global NtCreateCrossVmEvent
global NtGetPlugPlayEvent
global NtListTransactions
global NtMarshallTransaction
global NtPullTransaction
global NtReleaseCMFViewOwnership
global NtWaitForWnfNotifications
global NtStartTm
global NtSetInformationProcess
global NtRequestDeviceWakeup
global NtRequestWakeupLatency
global NtQuerySystemTime
global NtManageHotPatch
global NtContinueEx

global WhisperMain
extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret

NtAccessCheck:
    mov dword [currentHash], 018A0737Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWorkerFactoryWorkerReady:
    mov dword [currentHash], 09BA97DB3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcceptConnectPort:
    mov dword [currentHash], 068B11B5Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPagesScatter:
    mov dword [currentHash], 07FEE1137h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForSingleObject:
    mov dword [currentHash], 090BFA003h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallbackReturn:
    mov dword [currentHash], 01E941D38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFile:
    mov dword [currentHash], 0EA79D8E0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeviceIoControlFile:
    mov dword [currentHash], 07CF8ADCCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFile:
    mov dword [currentHash], 059C9C8FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletion:
    mov dword [currentHash], 00E886E1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseSemaphore:
    mov dword [currentHash], 044960E3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePort:
    mov dword [currentHash], 05930A25Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyPort:
    mov dword [currentHash], 02EBC2B22h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationThread:
    mov dword [currentHash], 0340FF225h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEvent:
    mov dword [currentHash], 008921512h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClose:
    mov dword [currentHash], 04495DDA1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryObject:
    mov dword [currentHash], 006286085h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationFile:
    mov dword [currentHash], 093356B21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKey:
    mov dword [currentHash], 0720A7393h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateValueKey:
    mov dword [currentHash], 0DA9ADD04h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFindAtom:
    mov dword [currentHash], 0322317BAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultLocale:
    mov dword [currentHash], 011287BAFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryKey:
    mov dword [currentHash], 0A672CB80h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryValueKey:
    mov dword [currentHash], 0982089B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemory:
    mov dword [currentHash], 0C1512DC6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationProcess:
    mov dword [currentHash], 0519E7C0Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects32:
    mov dword [currentHash], 03EAC1F7Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFileGather:
    mov dword [currentHash], 0318CE8A7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKey:
    mov dword [currentHash], 0104523FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeVirtualMemory:
    mov dword [currentHash], 001930F05h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateClientOfPort:
    mov dword [currentHash], 0396D26E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseMutant:
    mov dword [currentHash], 0BB168A93h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationToken:
    mov dword [currentHash], 08B9FF70Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWaitReplyPort:
    mov dword [currentHash], 020B04558h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVirtualMemory:
    mov dword [currentHash], 079917101h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadToken:
    mov dword [currentHash], 0FB531910h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationThread:
    mov dword [currentHash], 0144CD773h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcess:
    mov dword [currentHash], 0CE2CC5B1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationFile:
    mov dword [currentHash], 02D7D51A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSection:
    mov dword [currentHash], 060C9AE95h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckAndAuditAlarm:
    mov dword [currentHash], 030971C08h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSection:
    mov dword [currentHash], 008E02671h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePortEx:
    mov dword [currentHash], 0756F27B5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateProcess:
    mov dword [currentHash], 0C337DE9Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEventBoostPriority:
    mov dword [currentHash], 0D88FCC04h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFileScatter:
    mov dword [currentHash], 005AC0D37h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadTokenEx:
    mov dword [currentHash], 05A433EBEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessTokenEx:
    mov dword [currentHash], 064B1500Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPerformanceCounter:
    mov dword [currentHash], 07BED8581h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateKey:
    mov dword [currentHash], 0761F6184h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenFile:
    mov dword [currentHash], 0EA58F2EAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDelayExecution:
    mov dword [currentHash], 01AB51B26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFile:
    mov dword [currentHash], 0A8E240B0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformation:
    mov dword [currentHash], 0228A241Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSection:
    mov dword [currentHash], 08B23AB8Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimer:
    mov dword [currentHash], 0C99AF150h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFsControlFile:
    mov dword [currentHash], 03895E81Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 09B70CDAFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCloseObjectAuditAlarm:
    mov dword [currentHash], 016DB99C4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateObject:
    mov dword [currentHash], 02C050459h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAttributesFile:
    mov dword [currentHash], 0A6B5C6B2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearEvent:
    mov dword [currentHash], 07EA59CF0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadVirtualMemory:
    mov dword [currentHash], 03191351Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEvent:
    mov dword [currentHash], 0183371AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustPrivilegesToken:
    mov dword [currentHash], 06DDD5958h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateToken:
    mov dword [currentHash], 08350ADCCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinue:
    mov dword [currentHash], 02EA07164h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultUILanguage:
    mov dword [currentHash], 055D63014h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThread:
    mov dword [currentHash], 03CA43609h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtYieldExecution:
    mov dword [currentHash], 018B23A23h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtom:
    mov dword [currentHash], 03FB57C63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEvent:
    mov dword [currentHash], 011B0FFAAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVolumeInformationFile:
    mov dword [currentHash], 03575CE31h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSection:
    mov dword [currentHash], 0249304C1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFile:
    mov dword [currentHash], 01D5C1AC4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtApphelpCacheControl:
    mov dword [currentHash], 034624AA3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcessEx:
    mov dword [currentHash], 011B3E1CBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThread:
    mov dword [currentHash], 0922FDC85h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsProcessInJob:
    mov dword [currentHash], 0A8D15C80h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtProtectVirtualMemory:
    mov dword [currentHash], 08792CB57h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySection:
    mov dword [currentHash], 01A8C5E27h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeThread:
    mov dword [currentHash], 06AC0665Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateThread:
    mov dword [currentHash], 02A0B34A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadRequestData:
    mov dword [currentHash], 02E83F03Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateFile:
    mov dword [currentHash], 06756F762h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEvent:
    mov dword [currentHash], 08000E5E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteRequestData:
    mov dword [currentHash], 0621E52D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenDirectoryObject:
    mov dword [currentHash], 02A353AA9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeAndAuditAlarm:
    mov dword [currentHash], 00C53C00Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects:
    mov dword [currentHash], 051256B89h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationObject:
    mov dword [currentHash], 03C1704BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFile:
    mov dword [currentHash], 008B94C02h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceEvent:
    mov dword [currentHash], 02EB52126h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPowerInformation:
    mov dword [currentHash], 06688641Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetValueKey:
    mov dword [currentHash], 0E9392F67h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer:
    mov dword [currentHash], 0178326C0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer:
    mov dword [currentHash], 01DC52886h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByType:
    mov dword [currentHash], 0DC56E104h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultList:
    mov dword [currentHash], 0C972F3DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword [currentHash], 0C55AC9C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword [currentHash], 0C85426DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireProcessActivityReference:
    mov dword [currentHash], 01683D82Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtomEx:
    mov dword [currentHash], 041A9E191h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddBootEntry:
    mov dword [currentHash], 0458B7B2Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddDriverEntry:
    mov dword [currentHash], 00F972544h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustGroupsToken:
    mov dword [currentHash], 03D891114h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustTokenClaimsAndDeviceGroups:
    mov dword [currentHash], 07FE55ABDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertResumeThread:
    mov dword [currentHash], 01CB2020Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThread:
    mov dword [currentHash], 0380734AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThreadByThreadId:
    mov dword [currentHash], 009133583h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateLocallyUniqueId:
    mov dword [currentHash], 049AA1A9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateReserveObject:
    mov dword [currentHash], 03C8415D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUserPhysicalPages:
    mov dword [currentHash], 0FE65D1FFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUuids:
    mov dword [currentHash], 0110A3997h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemoryEx:
    mov dword [currentHash], 06C973072h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcAcceptConnectPort:
    mov dword [currentHash], 010B1033Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCancelMessage:
    mov dword [currentHash], 061550348h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPort:
    mov dword [currentHash], 01E8F2520h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPortEx:
    mov dword [currentHash], 033AE7155h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePort:
    mov dword [currentHash], 0E1B28661h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePortSection:
    mov dword [currentHash], 04ED3ADC1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateResourceReserve:
    mov dword [currentHash], 0FE6AE8DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSectionView:
    mov dword [currentHash], 042F6634Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSecurityContext:
    mov dword [currentHash], 0FE67EBCEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeletePortSection:
    mov dword [currentHash], 0108A121Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteResourceReserve:
    mov dword [currentHash], 038BCC8D7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSectionView:
    mov dword [currentHash], 007AEFAC8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSecurityContext:
    mov dword [currentHash], 0DA41CFE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDisconnectPort:
    mov dword [currentHash], 064F17F5Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientContainerOfPort:
    mov dword [currentHash], 03ABF3930h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientOfPort:
    mov dword [currentHash], 0E073EFE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderProcess:
    mov dword [currentHash], 0A1BEB813h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderThread:
    mov dword [currentHash], 01CBFD609h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformation:
    mov dword [currentHash], 0349C283Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformationMessage:
    mov dword [currentHash], 007BAC4E2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcRevokeSecurityContext:
    mov dword [currentHash], 0D74AC2EBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSendWaitReceivePort:
    mov dword [currentHash], 026B63B3Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSetInformation:
    mov dword [currentHash], 064C9605Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAreMappedFilesTheSame:
    mov dword [currentHash], 0AF96D807h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssignProcessToJobObject:
    mov dword [currentHash], 00622F45Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssociateWaitCompletionPacket:
    mov dword [currentHash], 01CBA4A67h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallEnclave:
    mov dword [currentHash], 02037B507h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFileEx:
    mov dword [currentHash], 058BA8AE0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelSynchronousIoFile:
    mov dword [currentHash], 0397931E9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer2:
    mov dword [currentHash], 0D794D342h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelWaitCompletionPacket:
    mov dword [currentHash], 0795C1FCEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitComplete:
    mov dword [currentHash], 09EC04A8Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitEnlistment:
    mov dword [currentHash], 07B258F42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitRegistryTransaction:
    mov dword [currentHash], 00AE60C77h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitTransaction:
    mov dword [currentHash], 03AAF0A0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompactKeys:
    mov dword [currentHash], 026471BD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareObjects:
    mov dword [currentHash], 049D54157h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareSigningLevels:
    mov dword [currentHash], 068C56852h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareTokens:
    mov dword [currentHash], 00D94050Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompleteConnectPort:
    mov dword [currentHash], 030B2196Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompressKey:
    mov dword [currentHash], 0D0A8E717h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConnectPort:
    mov dword [currentHash], 03EB03B22h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword [currentHash], 03795DD89h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDebugObject:
    mov dword [currentHash], 07AE3022Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObject:
    mov dword [currentHash], 03AA4760Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObjectEx:
    mov dword [currentHash], 042AEB0D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnclave:
    mov dword [currentHash], 05A1F9944h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnlistment:
    mov dword [currentHash], 079DC023Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEventPair:
    mov dword [currentHash], 034944A63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIRTimer:
    mov dword [currentHash], 0039635D2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIoCompletion:
    mov dword [currentHash], 09C929232h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobObject:
    mov dword [currentHash], 02D6903F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobSet:
    mov dword [currentHash], 0F3CEDF11h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyTransacted:
    mov dword [currentHash], 054BC1602h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyedEvent:
    mov dword [currentHash], 069329245h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateLowBoxToken:
    mov dword [currentHash], 067D8535Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMailslotFile:
    mov dword [currentHash], 02EBDB48Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMutant:
    mov dword [currentHash], 0BE119B48h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateNamedPipeFile:
    mov dword [currentHash], 096197812h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePagingFile:
    mov dword [currentHash], 074B2026Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePartition:
    mov dword [currentHash], 014825455h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePort:
    mov dword [currentHash], 01CB1E5DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePrivateNamespace:
    mov dword [currentHash], 04E908625h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcess:
    mov dword [currentHash], 05FDE4E52h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfile:
    mov dword [currentHash], 000DAF080h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfileEx:
    mov dword [currentHash], 0805BB2E1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateRegistryTransaction:
    mov dword [currentHash], 01E8E381Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateResourceManager:
    mov dword [currentHash], 0103302B8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSemaphore:
    mov dword [currentHash], 01D0FC3B4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSymbolicLinkObject:
    mov dword [currentHash], 09A26E8CBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 054AA9BDDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer:
    mov dword [currentHash], 0144622FFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer2:
    mov dword [currentHash], 0EB52365Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateToken:
    mov dword [currentHash], 020482AD1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTokenEx:
    mov dword [currentHash], 08A99CC66h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransaction:
    mov dword [currentHash], 0168C3411h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransactionManager:
    mov dword [currentHash], 0B22E98B3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateUserProcess:
    mov dword [currentHash], 065392CE4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitCompletionPacket:
    mov dword [currentHash], 0393C3BA2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitablePort:
    mov dword [currentHash], 020BD2726h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWnfStateName:
    mov dword [currentHash], 01CBECF89h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWorkerFactory:
    mov dword [currentHash], 02AA91E26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugActiveProcess:
    mov dword [currentHash], 08E248FABh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugContinue:
    mov dword [currentHash], 096119E7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteAtom:
    mov dword [currentHash], 0D27FF1E0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteBootEntry:
    mov dword [currentHash], 0C99D3CE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteDriverEntry:
    mov dword [currentHash], 0DF9315D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteFile:
    mov dword [currentHash], 0E278ECDCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteKey:
    mov dword [currentHash], 01FAB3208h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteObjectAuditAlarm:
    mov dword [currentHash], 01897120Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeletePrivateNamespace:
    mov dword [currentHash], 01EB55799h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteValueKey:
    mov dword [currentHash], 0A79A9224h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateData:
    mov dword [currentHash], 076BC4014h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateName:
    mov dword [currentHash], 00CC22507h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisableLastKnownGood:
    mov dword [currentHash], 0F82FF685h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisplayString:
    mov dword [currentHash], 01E8E2A1Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDrawText:
    mov dword [currentHash], 0D24BD7C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnableLastKnownGood:
    mov dword [currentHash], 09DCEAD19h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateBootEntries:
    mov dword [currentHash], 04C914109h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateDriverEntries:
    mov dword [currentHash], 034844D6Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateSystemEnvironmentValuesEx:
    mov dword [currentHash], 07FD24267h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateTransactionObject:
    mov dword [currentHash], 06AB56A29h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtExtendSection:
    mov dword [currentHash], 038A81E21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterBootOption:
    mov dword [currentHash], 03A92D781h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterToken:
    mov dword [currentHash], 0E55CD3D8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterTokenEx:
    mov dword [currentHash], 00484F1F9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFileEx:
    mov dword [currentHash], 00B9845AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstallUILanguage:
    mov dword [currentHash], 0F557C2CEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstructionCache:
    mov dword [currentHash], 0693F9567h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushKey:
    mov dword [currentHash], 0D461E3DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushProcessWriteBuffers:
    mov dword [currentHash], 07EBC7E2Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushVirtualMemory:
    mov dword [currentHash], 0B31C89AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushWriteBuffer:
    mov dword [currentHash], 06BC0429Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeUserPhysicalPages:
    mov dword [currentHash], 011BC2A12h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeRegistry:
    mov dword [currentHash], 026452CC5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeTransactions:
    mov dword [currentHash], 013CB00ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCachedSigningLevel:
    mov dword [currentHash], 0B28BB815h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCompleteWnfStateSubscription:
    mov dword [currentHash], 044CB0A13h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetContextThread:
    mov dword [currentHash], 06B4E279Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumber:
    mov dword [currentHash], 006937878h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumberEx:
    mov dword [currentHash], 084EAA254h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetDevicePowerState:
    mov dword [currentHash], 0B49BA434h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetMUIRegistryInfo:
    mov dword [currentHash], 084B7B211h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextProcess:
    mov dword [currentHash], 01B9E1E0Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextThread:
    mov dword [currentHash], 0EE4B2CEDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNlsSectionPtr:
    mov dword [currentHash], 02B12C80Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNotificationResourceManager:
    mov dword [currentHash], 0823CAA87h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetWriteWatch:
    mov dword [currentHash], 0105E2CDAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateAnonymousToken:
    mov dword [currentHash], 04550AA4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateThread:
    mov dword [currentHash], 0B000BAAEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeEnclave:
    mov dword [currentHash], 02C93C098h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeNlsFiles:
    mov dword [currentHash], 06CECA3B6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeRegistry:
    mov dword [currentHash], 0BC533055h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitiatePowerAction:
    mov dword [currentHash], 0CB578F84h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsSystemResumeAutomatic:
    mov dword [currentHash], 00440C162h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsUILanguageComitted:
    mov dword [currentHash], 027AA3515h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListenPort:
    mov dword [currentHash], 0E173E0FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadDriver:
    mov dword [currentHash], 012B81A26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadEnclaveData:
    mov dword [currentHash], 0849AD429h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadHotPatch:
    mov dword [currentHash], 0ECA229FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey:
    mov dword [currentHash], 0083A69A3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey2:
    mov dword [currentHash], 0AB3221EEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKeyEx:
    mov dword [currentHash], 07399B624h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockFile:
    mov dword [currentHash], 03A3D365Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockProductActivationKeys:
    mov dword [currentHash], 04F3248A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockRegistryKey:
    mov dword [currentHash], 0DEABF13Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockVirtualMemory:
    mov dword [currentHash], 00794EEFBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakePermanentObject:
    mov dword [currentHash], 0A13ECFE4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakeTemporaryObject:
    mov dword [currentHash], 01E3D74A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManagePartition:
    mov dword [currentHash], 00AE16A33h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapCMFModule:
    mov dword [currentHash], 0169B1AFCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPages:
    mov dword [currentHash], 029B5721Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSectionEx:
    mov dword [currentHash], 0365CF80Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyBootEntry:
    mov dword [currentHash], 0099AFCE1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyDriverEntry:
    mov dword [currentHash], 021C8CD98h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFile:
    mov dword [currentHash], 0AA3A816Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFileEx:
    mov dword [currentHash], 08B54FFA8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeKey:
    mov dword [currentHash], 0F1FBD3A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeMultipleKeys:
    mov dword [currentHash], 065BE7236h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeSession:
    mov dword [currentHash], 001890314h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEnlistment:
    mov dword [currentHash], 05BD55E63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEventPair:
    mov dword [currentHash], 020944861h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenIoCompletion:
    mov dword [currentHash], 07067F071h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenJobObject:
    mov dword [currentHash], 0F341013Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyEx:
    mov dword [currentHash], 00F99C3DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransacted:
    mov dword [currentHash], 0104416DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransactedEx:
    mov dword [currentHash], 0889ABA21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyedEvent:
    mov dword [currentHash], 0E87FEBE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenMutant:
    mov dword [currentHash], 0B22DF5FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenObjectAuditAlarm:
    mov dword [currentHash], 02AAD0E7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPartition:
    mov dword [currentHash], 0108DD0DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPrivateNamespace:
    mov dword [currentHash], 0785F07BDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessToken:
    mov dword [currentHash], 0E75BFBEAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenRegistryTransaction:
    mov dword [currentHash], 09CC47B51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenResourceManager:
    mov dword [currentHash], 0F9512419h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSemaphore:
    mov dword [currentHash], 09306CBBBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSession:
    mov dword [currentHash], 0D2053455h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSymbolicLinkObject:
    mov dword [currentHash], 00A943819h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThread:
    mov dword [currentHash], 0183F5496h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTimer:
    mov dword [currentHash], 00B189804h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransaction:
    mov dword [currentHash], 09C089C9Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransactionManager:
    mov dword [currentHash], 005E791C6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPlugPlayControl:
    mov dword [currentHash], 0C6693A38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareComplete:
    mov dword [currentHash], 0089003FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareEnlistment:
    mov dword [currentHash], 0F9A71DCCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareComplete:
    mov dword [currentHash], 004D057EEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareEnlistment:
    mov dword [currentHash], 0D9469E8Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeCheck:
    mov dword [currentHash], 028950FC5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeObjectAuditAlarm:
    mov dword [currentHash], 0E12EDD61h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegedServiceAuditAlarm:
    mov dword [currentHash], 012B41622h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationComplete:
    mov dword [currentHash], 00E913E3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationFailed:
    mov dword [currentHash], 04ED9AF84h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPulseEvent:
    mov dword [currentHash], 0000A1B9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAuxiliaryCounterFrequency:
    mov dword [currentHash], 0EAD9F64Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootEntryOrder:
    mov dword [currentHash], 0F7EEFB75h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootOptions:
    mov dword [currentHash], 0178D1F1Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDebugFilterState:
    mov dword [currentHash], 074CA7E6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFileEx:
    mov dword [currentHash], 0C8530A69h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryObject:
    mov dword [currentHash], 0E65ACF07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDriverEntryOrder:
    mov dword [currentHash], 013461DDBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEaFile:
    mov dword [currentHash], 0E4A4944Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryFullAttributesFile:
    mov dword [currentHash], 0C6CDC662h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationAtom:
    mov dword [currentHash], 09B07BA93h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationByName:
    mov dword [currentHash], 0A80AAF91h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationEnlistment:
    mov dword [currentHash], 02FB12E23h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationJobObject:
    mov dword [currentHash], 007A5C2EBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationPort:
    mov dword [currentHash], 0A73AA8A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationResourceManager:
    mov dword [currentHash], 007B6EEEEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransaction:
    mov dword [currentHash], 002ED227Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransactionManager:
    mov dword [currentHash], 0B32C9DB0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationWorkerFactory:
    mov dword [currentHash], 0CC9A2E03h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInstallUILanguage:
    mov dword [currentHash], 04FC9365Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIntervalProfile:
    mov dword [currentHash], 0D73B26AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIoCompletion:
    mov dword [currentHash], 05ED55E47h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryLicenseValue:
    mov dword [currentHash], 0D4433CCCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMultipleValueKey:
    mov dword [currentHash], 0825AF1A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMutant:
    mov dword [currentHash], 0DE19F380h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeys:
    mov dword [currentHash], 00DB3606Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeysEx:
    mov dword [currentHash], 061DAB182h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPortInformationProcess:
    mov dword [currentHash], 069306CA8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryQuotaInformationFile:
    mov dword [currentHash], 0E2B83781h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityAttributesToken:
    mov dword [currentHash], 07D27A48Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityObject:
    mov dword [currentHash], 013BCE0C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityPolicy:
    mov dword [currentHash], 005AAE1D7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySemaphore:
    mov dword [currentHash], 03AAA6416h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySymbolicLinkObject:
    mov dword [currentHash], 01702E100h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValue:
    mov dword [currentHash], 0CA9129DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValueEx:
    mov dword [currentHash], 0534A0796h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformationEx:
    mov dword [currentHash], 09694C44Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimerResolution:
    mov dword [currentHash], 0C24DE4D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateData:
    mov dword [currentHash], 0A3039595h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateNameInformation:
    mov dword [currentHash], 0FAEB18E7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThreadEx:
    mov dword [currentHash], 0FCACFE16h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseException:
    mov dword [currentHash], 03F6E1A3Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseHardError:
    mov dword [currentHash], 0CF5CD1CDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadOnlyEnlistment:
    mov dword [currentHash], 09236B7A4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverEnlistment:
    mov dword [currentHash], 0C8530818h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverResourceManager:
    mov dword [currentHash], 0605F52FCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverTransactionManager:
    mov dword [currentHash], 006379837h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterProtocolAddressInformation:
    mov dword [currentHash], 0049326C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterThreadTerminatePort:
    mov dword [currentHash], 0EE76DE3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseKeyedEvent:
    mov dword [currentHash], 0DB88FCD3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseWorkerFactoryWorker:
    mov dword [currentHash], 03E9FE8BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletionEx:
    mov dword [currentHash], 06496A2E8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveProcessDebug:
    mov dword [currentHash], 0CA5FCBF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameKey:
    mov dword [currentHash], 0E9DF04ACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameTransactionManager:
    mov dword [currentHash], 005B75116h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplaceKey:
    mov dword [currentHash], 0DD58FCC2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplacePartitionUnit:
    mov dword [currentHash], 0AEAF5BD5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReplyPort:
    mov dword [currentHash], 0E47EE1EEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestPort:
    mov dword [currentHash], 0E073F9F6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetEvent:
    mov dword [currentHash], 0DC313C62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetWriteWatch:
    mov dword [currentHash], 012DF2E5Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRestoreKey:
    mov dword [currentHash], 02BFE4615h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeProcess:
    mov dword [currentHash], 083D37ABEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRevertContainerImpersonation:
    mov dword [currentHash], 00895C8C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackComplete:
    mov dword [currentHash], 054B85056h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackEnlistment:
    mov dword [currentHash], 0D9469E8Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackRegistryTransaction:
    mov dword [currentHash], 010B7F7E2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackTransaction:
    mov dword [currentHash], 003D73B7Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollforwardTransactionManager:
    mov dword [currentHash], 00D339D2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKey:
    mov dword [currentHash], 077CB5654h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKeyEx:
    mov dword [currentHash], 01790EBE4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveMergedKeys:
    mov dword [currentHash], 025A32A3Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSecureConnectPort:
    mov dword [currentHash], 0128D0102h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSerializeBoot:
    mov dword [currentHash], 097421756h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootEntryOrder:
    mov dword [currentHash], 0B16B8BC3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootOptions:
    mov dword [currentHash], 007990D1Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel:
    mov dword [currentHash], 022BB2406h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel2:
    mov dword [currentHash], 02499AD4Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetContextThread:
    mov dword [currentHash], 0268C2825h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDebugFilterState:
    mov dword [currentHash], 0D749D8EDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultHardErrorPort:
    mov dword [currentHash], 0FB72E0FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultLocale:
    mov dword [currentHash], 0BC24BA98h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultUILanguage:
    mov dword [currentHash], 0A40A192Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDriverEntryOrder:
    mov dword [currentHash], 0B7998D35h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEaFile:
    mov dword [currentHash], 0BD2A4348h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighEventPair:
    mov dword [currentHash], 044CC405Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighWaitLowEventPair:
    mov dword [currentHash], 050D47445h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIRTimer:
    mov dword [currentHash], 0FF5D1906h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationDebugObject:
    mov dword [currentHash], 01C21E44Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationEnlistment:
    mov dword [currentHash], 0C054E1C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationJobObject:
    mov dword [currentHash], 08FA0B52Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationKey:
    mov dword [currentHash], 0D859E5FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationResourceManager:
    mov dword [currentHash], 0E3C7FF6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationSymbolicLink:
    mov dword [currentHash], 06EF76E62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationToken:
    mov dword [currentHash], 08D088394h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransaction:
    mov dword [currentHash], 0174BCAE0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransactionManager:
    mov dword [currentHash], 001B56948h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationVirtualMemory:
    mov dword [currentHash], 019901D1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationWorkerFactory:
    mov dword [currentHash], 084509CCEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIntervalProfile:
    mov dword [currentHash], 0EC263464h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletion:
    mov dword [currentHash], 0C030E6A5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletionEx:
    mov dword [currentHash], 02695F9C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLdtEntries:
    mov dword [currentHash], 08CA4FF44h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowEventPair:
    mov dword [currentHash], 011923702h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowWaitHighEventPair:
    mov dword [currentHash], 004DC004Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetQuotaInformationFile:
    mov dword [currentHash], 09E3DA8AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSecurityObject:
    mov dword [currentHash], 0D847888Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValue:
    mov dword [currentHash], 01E88F888h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValueEx:
    mov dword [currentHash], 01C0124BEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemInformation:
    mov dword [currentHash], 0D9B6DF25h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemPowerState:
    mov dword [currentHash], 0D950A7D2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemTime:
    mov dword [currentHash], 03EAB4F3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetThreadExecutionState:
    mov dword [currentHash], 08204E480h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer2:
    mov dword [currentHash], 09BD89B16h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerEx:
    mov dword [currentHash], 0B54085F8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerResolution:
    mov dword [currentHash], 054C27455h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetUuidSeed:
    mov dword [currentHash], 07458C176h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetVolumeInformationFile:
    mov dword [currentHash], 01EBFD488h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetWnfProcessNotificationEvent:
    mov dword [currentHash], 01288F19Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownSystem:
    mov dword [currentHash], 0CCEDF547h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownWorkerFactory:
    mov dword [currentHash], 0C452D8B7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSignalAndWaitForSingleObject:
    mov dword [currentHash], 0A63B9E97h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSinglePhaseReject:
    mov dword [currentHash], 0223C44CFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartProfile:
    mov dword [currentHash], 0815AD3EFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStopProfile:
    mov dword [currentHash], 0049DCAB8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSubscribeWnfStateChange:
    mov dword [currentHash], 09E39D3E0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendProcess:
    mov dword [currentHash], 0315E32C0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendThread:
    mov dword [currentHash], 036932821h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSystemDebugControl:
    mov dword [currentHash], 0019FF3D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateEnclave:
    mov dword [currentHash], 060BF7434h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateJobObject:
    mov dword [currentHash], 0049F5245h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTestAlert:
    mov dword [currentHash], 0CF52DAF3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawRegistry:
    mov dword [currentHash], 0C2A133E8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawTransactions:
    mov dword [currentHash], 077E74B55h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceControl:
    mov dword [currentHash], 03FA9F9F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTranslateFilePath:
    mov dword [currentHash], 0FF56FCCDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUmsThreadYield:
    mov dword [currentHash], 08F159CA1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadDriver:
    mov dword [currentHash], 0DD6A2061h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey:
    mov dword [currentHash], 068BD075Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey2:
    mov dword [currentHash], 033D56F58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKeyEx:
    mov dword [currentHash], 029E71F58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockFile:
    mov dword [currentHash], 02A7B5CEFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockVirtualMemory:
    mov dword [currentHash], 0FFA8C917h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSectionEx:
    mov dword [currentHash], 04A914E2Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnsubscribeWnfStateChange:
    mov dword [currentHash], 0EA3FB7FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUpdateWnfStateData:
    mov dword [currentHash], 0CD02DFB3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtVdmControl:
    mov dword [currentHash], 08B9012A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForAlertByThreadId:
    mov dword [currentHash], 046BA6C7Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForDebugEvent:
    mov dword [currentHash], 000CF1D66h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForKeyedEvent:
    mov dword [currentHash], 090CA6AADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWorkViaWorkerFactory:
    mov dword [currentHash], 0F8AED47Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitHighEventPair:
    mov dword [currentHash], 0D34FC1D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitLowEventPair:
    mov dword [currentHash], 0B4165C0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireCMFViewOwnership:
    mov dword [currentHash], 06AD32A5Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelDeviceWakeupRequest:
    mov dword [currentHash], 0F7BC10D7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearAllSavepointsTransaction:
    mov dword [currentHash], 0C089E259h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearSavepointTransaction:
    mov dword [currentHash], 0F56929C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackSavepointTransaction:
    mov dword [currentHash], 0D843FA97h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointTransaction:
    mov dword [currentHash], 09813DAC7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointComplete:
    mov dword [currentHash], 088DA86B3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSectionEx:
    mov dword [currentHash], 0B053F2E9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateCrossVmEvent:
    mov dword [currentHash], 0FE3CC196h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetPlugPlayEvent:
    mov dword [currentHash], 000902D08h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListTransactions:
    mov dword [currentHash], 08525A983h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMarshallTransaction:
    mov dword [currentHash], 0905B92CFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPullTransaction:
    mov dword [currentHash], 0900BD6DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseCMFViewOwnership:
    mov dword [currentHash], 08E15828Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWnfNotifications:
    mov dword [currentHash], 0DC8FDA1Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartTm:
    mov dword [currentHash], 0031E49A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationProcess:
    mov dword [currentHash], 08117868Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestDeviceWakeup:
    mov dword [currentHash], 0359314C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWakeupLatency:
    mov dword [currentHash], 09801A1BCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemTime:
    mov dword [currentHash], 0B9A357A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManageHotPatch:
    mov dword [currentHash], 0A0BF2EA8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinueEx:
    mov dword [currentHash], 05FC5BBB9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

