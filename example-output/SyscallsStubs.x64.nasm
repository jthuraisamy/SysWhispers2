[SECTION .data]
currentHash:    dw  0

[SECTION .text]

BITS 64

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
global RtlCreateUserThread

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
    mov dword [currentHash], 0FA40F4F9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWorkerFactoryWorkerReady:
    mov dword [currentHash], 011A63B35h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcceptConnectPort:
    mov dword [currentHash], 064F17B62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPagesScatter:
    mov dword [currentHash], 0238A0D17h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForSingleObject:
    mov dword [currentHash], 0009E3E33h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallbackReturn:
    mov dword [currentHash], 0168C371Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFile:
    mov dword [currentHash], 0C544CDF1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeviceIoControlFile:
    mov dword [currentHash], 022342AD2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFile:
    mov dword [currentHash], 0E97AEB1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletion:
    mov dword [currentHash], 0088E0821h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseSemaphore:
    mov dword [currentHash], 034A10CFCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePort:
    mov dword [currentHash], 0ACFE8EA0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyPort:
    mov dword [currentHash], 062B0692Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationThread:
    mov dword [currentHash], 00A2E4E86h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEvent:
    mov dword [currentHash], 058924AF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClose:
    mov dword [currentHash], 00352369Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryObject:
    mov dword [currentHash], 08CA077CCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationFile:
    mov dword [currentHash], 0A635B086h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKey:
    mov dword [currentHash], 00F1A54C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateValueKey:
    mov dword [currentHash], 016AB2319h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFindAtom:
    mov dword [currentHash], 03565D433h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultLocale:
    mov dword [currentHash], 0025D728Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryKey:
    mov dword [currentHash], 008172BACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryValueKey:
    mov dword [currentHash], 0E15C142Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemory:
    mov dword [currentHash], 01F88E9E7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationProcess:
    mov dword [currentHash], 0D99B2213h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects32:
    mov dword [currentHash], 08E9DAF4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFileGather:
    mov dword [currentHash], 02B907B53h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKey:
    mov dword [currentHash], 07EC9073Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeVirtualMemory:
    mov dword [currentHash], 0099E0519h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateClientOfPort:
    mov dword [currentHash], 060F36F68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseMutant:
    mov dword [currentHash], 02D4A0AD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationToken:
    mov dword [currentHash], 035AA1F32h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWaitReplyPort:
    mov dword [currentHash], 0E273D9DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVirtualMemory:
    mov dword [currentHash], 09514A39Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadToken:
    mov dword [currentHash], 0F8512DEAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationThread:
    mov dword [currentHash], 024881E11h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcess:
    mov dword [currentHash], 006AC0521h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationFile:
    mov dword [currentHash], 0CA7AC2ECh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSection:
    mov dword [currentHash], 004960E0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckAndAuditAlarm:
    mov dword [currentHash], 00F2EC371h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSection:
    mov dword [currentHash], 0568C3591h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePortEx:
    mov dword [currentHash], 0A25FEA98h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateProcess:
    mov dword [currentHash], 0FE26D5BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEventBoostPriority:
    mov dword [currentHash], 030863C0Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFileScatter:
    mov dword [currentHash], 0159C1D07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadTokenEx:
    mov dword [currentHash], 02FBAF2EFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessTokenEx:
    mov dword [currentHash], 0791FB957h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPerformanceCounter:
    mov dword [currentHash], 037D24B39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateKey:
    mov dword [currentHash], 0B6AE97F4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenFile:
    mov dword [currentHash], 0AD1C2B01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDelayExecution:
    mov dword [currentHash], 0520D529Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFile:
    mov dword [currentHash], 058BBAAE2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformation:
    mov dword [currentHash], 054CD765Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSection:
    mov dword [currentHash], 00A9E284Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimer:
    mov dword [currentHash], 0179F7F46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFsControlFile:
    mov dword [currentHash], 06AF45662h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 005953B23h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCloseObjectAuditAlarm:
    mov dword [currentHash], 05CDA584Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateObject:
    mov dword [currentHash], 03EA1F6FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAttributesFile:
    mov dword [currentHash], 0DD5DD9FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearEvent:
    mov dword [currentHash], 0200B65DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadVirtualMemory:
    mov dword [currentHash], 0071473E9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEvent:
    mov dword [currentHash], 030D52978h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustPrivilegesToken:
    mov dword [currentHash], 001940B2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateToken:
    mov dword [currentHash], 06DD92558h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinue:
    mov dword [currentHash], 0009CD3D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultUILanguage:
    mov dword [currentHash], 013C5D178h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThread:
    mov dword [currentHash], 02E8A0C2Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtYieldExecution:
    mov dword [currentHash], 014B63E33h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtom:
    mov dword [currentHash], 022BF272Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEvent:
    mov dword [currentHash], 0B0B4AF3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVolumeInformationFile:
    mov dword [currentHash], 0E5B3BD76h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSection:
    mov dword [currentHash], 04EC54C51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFile:
    mov dword [currentHash], 06CFB5E2Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtApphelpCacheControl:
    mov dword [currentHash], 0FD6DDFBBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcessEx:
    mov dword [currentHash], 0B998FB42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThread:
    mov dword [currentHash], 0AF8CB334h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsProcessInJob:
    mov dword [currentHash], 05CE54854h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtProtectVirtualMemory:
    mov dword [currentHash], 00F940311h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySection:
    mov dword [currentHash], 002EC25B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeThread:
    mov dword [currentHash], 07D5445CFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateThread:
    mov dword [currentHash], 0228E3037h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadRequestData:
    mov dword [currentHash], 0A23EB14Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateFile:
    mov dword [currentHash], 02A9AE32Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEvent:
    mov dword [currentHash], 02AB1F0E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteRequestData:
    mov dword [currentHash], 09DC08975h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenDirectoryObject:
    mov dword [currentHash], 03C802E0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeAndAuditAlarm:
    mov dword [currentHash], 0DD42B9D5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects:
    mov dword [currentHash], 061AD6331h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationObject:
    mov dword [currentHash], 0271915A7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFile:
    mov dword [currentHash], 0821B7543h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceEvent:
    mov dword [currentHash], 0CAED7BD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPowerInformation:
    mov dword [currentHash], 054C25A5Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetValueKey:
    mov dword [currentHash], 01DC11E58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer:
    mov dword [currentHash], 001A23302h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer:
    mov dword [currentHash], 005977F7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByType:
    mov dword [currentHash], 0D442E30Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultList:
    mov dword [currentHash], 07EA17221h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword [currentHash], 0552A6982h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword [currentHash], 099B41796h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireProcessActivityReference:
    mov dword [currentHash], 01A8958A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtomEx:
    mov dword [currentHash], 09390C74Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddBootEntry:
    mov dword [currentHash], 005951912h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddDriverEntry:
    mov dword [currentHash], 03B67B174h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustGroupsToken:
    mov dword [currentHash], 025971314h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustTokenClaimsAndDeviceGroups:
    mov dword [currentHash], 007900309h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertResumeThread:
    mov dword [currentHash], 0A48BA81Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThread:
    mov dword [currentHash], 01CA4540Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThreadByThreadId:
    mov dword [currentHash], 0B8A26896h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateLocallyUniqueId:
    mov dword [currentHash], 0FFE51B65h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateReserveObject:
    mov dword [currentHash], 018B4E6C9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUserPhysicalPages:
    mov dword [currentHash], 019BF3A24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUuids:
    mov dword [currentHash], 0338FFDD3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemoryEx:
    mov dword [currentHash], 0C8503B3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcAcceptConnectPort:
    mov dword [currentHash], 030B2213Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCancelMessage:
    mov dword [currentHash], 073D77E7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPort:
    mov dword [currentHash], 03EB1DDDEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPortEx:
    mov dword [currentHash], 0636DBF29h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePort:
    mov dword [currentHash], 0194B9F58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePortSection:
    mov dword [currentHash], 0C4F5DE41h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateResourceReserve:
    mov dword [currentHash], 0389F4A77h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSectionView:
    mov dword [currentHash], 02CA81D13h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSecurityContext:
    mov dword [currentHash], 0FA1DE794h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeletePortSection:
    mov dword [currentHash], 00C982C0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteResourceReserve:
    mov dword [currentHash], 01888F4C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSectionView:
    mov dword [currentHash], 056EC6753h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSecurityContext:
    mov dword [currentHash], 008B3EDDAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDisconnectPort:
    mov dword [currentHash], 022B5D93Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientContainerOfPort:
    mov dword [currentHash], 02233A722h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientOfPort:
    mov dword [currentHash], 0D836C9DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderProcess:
    mov dword [currentHash], 0C654C5C9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderThread:
    mov dword [currentHash], 0F85F36EDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformation:
    mov dword [currentHash], 0024618CEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformationMessage:
    mov dword [currentHash], 0A40091ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcRevokeSecurityContext:
    mov dword [currentHash], 040998DC8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSendWaitReceivePort:
    mov dword [currentHash], 022B2A5B8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSetInformation:
    mov dword [currentHash], 0C897E64Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAreMappedFilesTheSame:
    mov dword [currentHash], 0D65AEDFDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssignProcessToJobObject:
    mov dword [currentHash], 0FF2A6100h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssociateWaitCompletionPacket:
    mov dword [currentHash], 007B22910h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallEnclave:
    mov dword [currentHash], 08736BB65h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFileEx:
    mov dword [currentHash], 0F758392Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelSynchronousIoFile:
    mov dword [currentHash], 0256033EAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer2:
    mov dword [currentHash], 003A35E2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelWaitCompletionPacket:
    mov dword [currentHash], 0BC9C9AC6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitComplete:
    mov dword [currentHash], 00C9007FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitEnlistment:
    mov dword [currentHash], 0164B0FC6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitRegistryTransaction:
    mov dword [currentHash], 004B43E31h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitTransaction:
    mov dword [currentHash], 018813A51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompactKeys:
    mov dword [currentHash], 057BA6A14h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareObjects:
    mov dword [currentHash], 084648AF6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareSigningLevels:
    mov dword [currentHash], 0AEF09E73h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareTokens:
    mov dword [currentHash], 0F494EC01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompleteConnectPort:
    mov dword [currentHash], 03A7637F8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompressKey:
    mov dword [currentHash], 0782E5F8Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConnectPort:
    mov dword [currentHash], 0A23C9072h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword [currentHash], 079468945h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDebugObject:
    mov dword [currentHash], 0009E21C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObject:
    mov dword [currentHash], 0FAD436BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObjectEx:
    mov dword [currentHash], 0426E10B4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnclave:
    mov dword [currentHash], 0CA2FDE86h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnlistment:
    mov dword [currentHash], 00F90ECC7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEventPair:
    mov dword [currentHash], 012B1CCFCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIRTimer:
    mov dword [currentHash], 0178C3F36h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIoCompletion:
    mov dword [currentHash], 00E1750D7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobObject:
    mov dword [currentHash], 0F65B6E57h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobSet:
    mov dword [currentHash], 08740AF1Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyTransacted:
    mov dword [currentHash], 0A69A66C6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyedEvent:
    mov dword [currentHash], 068CF755Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateLowBoxToken:
    mov dword [currentHash], 017C73D1Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMailslotFile:
    mov dword [currentHash], 0E47DC2FEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMutant:
    mov dword [currentHash], 0FDDC08A5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateNamedPipeFile:
    mov dword [currentHash], 0ED7AA75Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePagingFile:
    mov dword [currentHash], 054C36C00h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePartition:
    mov dword [currentHash], 0444E255Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePort:
    mov dword [currentHash], 02EB4CCDAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePrivateNamespace:
    mov dword [currentHash], 009B1CFEBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcess:
    mov dword [currentHash], 081288EB0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfile:
    mov dword [currentHash], 06E3E6AA4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfileEx:
    mov dword [currentHash], 0029AC0C1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateRegistryTransaction:
    mov dword [currentHash], 0970FD3DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateResourceManager:
    mov dword [currentHash], 06E52FA4Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSemaphore:
    mov dword [currentHash], 0FCB62D1Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSymbolicLinkObject:
    mov dword [currentHash], 083189384h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 096A7CC64h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer:
    mov dword [currentHash], 0E58D8F55h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer2:
    mov dword [currentHash], 0B0684CA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateToken:
    mov dword [currentHash], 0099F9FBFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTokenEx:
    mov dword [currentHash], 06022A67Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransaction:
    mov dword [currentHash], 03CEE2243h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransactionManager:
    mov dword [currentHash], 01BA730FAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateUserProcess:
    mov dword [currentHash], 0EC26CFBBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitCompletionPacket:
    mov dword [currentHash], 001813F0Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitablePort:
    mov dword [currentHash], 0A97288DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWnfStateName:
    mov dword [currentHash], 0CED0FB42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWorkerFactory:
    mov dword [currentHash], 0089C140Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugActiveProcess:
    mov dword [currentHash], 0923099ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugContinue:
    mov dword [currentHash], 05D24BC68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteAtom:
    mov dword [currentHash], 0BED35C8Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteBootEntry:
    mov dword [currentHash], 0336B3BE4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteDriverEntry:
    mov dword [currentHash], 033930B14h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteFile:
    mov dword [currentHash], 06EF46592h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteKey:
    mov dword [currentHash], 03AEE1D71h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteObjectAuditAlarm:
    mov dword [currentHash], 016B57464h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeletePrivateNamespace:
    mov dword [currentHash], 02A88393Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteValueKey:
    mov dword [currentHash], 036820931h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateData:
    mov dword [currentHash], 032CE441Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateName:
    mov dword [currentHash], 0A8B02387h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisableLastKnownGood:
    mov dword [currentHash], 0386B35C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisplayString:
    mov dword [currentHash], 076E83238h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDrawText:
    mov dword [currentHash], 04918735Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnableLastKnownGood:
    mov dword [currentHash], 02DBE03F4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateBootEntries:
    mov dword [currentHash], 02C97BD9Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateDriverEntries:
    mov dword [currentHash], 07CDC2D7Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateSystemEnvironmentValuesEx:
    mov dword [currentHash], 053AF8FFBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateTransactionObject:
    mov dword [currentHash], 096B4A608h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtExtendSection:
    mov dword [currentHash], 00E8A340Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterBootOption:
    mov dword [currentHash], 008A20BCFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterToken:
    mov dword [currentHash], 07FD56972h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterTokenEx:
    mov dword [currentHash], 08E59B5DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFileEx:
    mov dword [currentHash], 026D4E08Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstallUILanguage:
    mov dword [currentHash], 0A5BAD1A1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstructionCache:
    mov dword [currentHash], 00DAE4997h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushKey:
    mov dword [currentHash], 09ED4BF6Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushProcessWriteBuffers:
    mov dword [currentHash], 0D83A3DA2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushVirtualMemory:
    mov dword [currentHash], 08713938Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushWriteBuffer:
    mov dword [currentHash], 0A538B5A7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeUserPhysicalPages:
    mov dword [currentHash], 0E5BEEE26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeRegistry:
    mov dword [currentHash], 0069B203Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeTransactions:
    mov dword [currentHash], 04FAA257Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCachedSigningLevel:
    mov dword [currentHash], 076BCA01Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCompleteWnfStateSubscription:
    mov dword [currentHash], 0148F1A13h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetContextThread:
    mov dword [currentHash], 00C9C1E2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumber:
    mov dword [currentHash], 08E33C8E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumberEx:
    mov dword [currentHash], 05AD599AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetDevicePowerState:
    mov dword [currentHash], 0A43BB4B4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetMUIRegistryInfo:
    mov dword [currentHash], 07ACEA663h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextProcess:
    mov dword [currentHash], 00DA3362Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextThread:
    mov dword [currentHash], 09A3DD48Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNlsSectionPtr:
    mov dword [currentHash], 0FF5DD282h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNotificationResourceManager:
    mov dword [currentHash], 0EFB2719Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetWriteWatch:
    mov dword [currentHash], 08AA31383h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateAnonymousToken:
    mov dword [currentHash], 03F8F0F22h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateThread:
    mov dword [currentHash], 0FA202799h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeEnclave:
    mov dword [currentHash], 02C9310D2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeNlsFiles:
    mov dword [currentHash], 0744F05ACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeRegistry:
    mov dword [currentHash], 034901C3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitiatePowerAction:
    mov dword [currentHash], 0C690DF3Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsSystemResumeAutomatic:
    mov dword [currentHash], 0A4A02186h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsUILanguageComitted:
    mov dword [currentHash], 0D5EB91C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListenPort:
    mov dword [currentHash], 0DCB0DF3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadDriver:
    mov dword [currentHash], 01C9F4E5Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadEnclaveData:
    mov dword [currentHash], 0074E907Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadHotPatch:
    mov dword [currentHash], 09F721D4Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey:
    mov dword [currentHash], 03F1844E5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey2:
    mov dword [currentHash], 0DA270AA1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKeyEx:
    mov dword [currentHash], 0BBFD8746h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockFile:
    mov dword [currentHash], 0E17FCDAFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockProductActivationKeys:
    mov dword [currentHash], 067E66A7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockRegistryKey:
    mov dword [currentHash], 0130628B6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockVirtualMemory:
    mov dword [currentHash], 00B981D77h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakePermanentObject:
    mov dword [currentHash], 0243B2EA5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakeTemporaryObject:
    mov dword [currentHash], 0263B5ED7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManagePartition:
    mov dword [currentHash], 008B1E6EDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapCMFModule:
    mov dword [currentHash], 03917A320h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPages:
    mov dword [currentHash], 01142E82Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSectionEx:
    mov dword [currentHash], 0BE9CE842h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyBootEntry:
    mov dword [currentHash], 009941D38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyDriverEntry:
    mov dword [currentHash], 071E16D64h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFile:
    mov dword [currentHash], 01999E00Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFileEx:
    mov dword [currentHash], 06B97BFCBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeKey:
    mov dword [currentHash], 0CB12AAE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeMultipleKeys:
    mov dword [currentHash], 07F837404h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeSession:
    mov dword [currentHash], 0E78FE71Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEnlistment:
    mov dword [currentHash], 0BABADD51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEventPair:
    mov dword [currentHash], 090B047E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenIoCompletion:
    mov dword [currentHash], 00C656AADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenJobObject:
    mov dword [currentHash], 0429C0E63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyEx:
    mov dword [currentHash], 06BDD9BA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransacted:
    mov dword [currentHash], 010CD1A62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransactedEx:
    mov dword [currentHash], 086AEC878h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyedEvent:
    mov dword [currentHash], 050CB5D4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenMutant:
    mov dword [currentHash], 01693FCC5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenObjectAuditAlarm:
    mov dword [currentHash], 074B25FF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPartition:
    mov dword [currentHash], 00ABA2FF1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPrivateNamespace:
    mov dword [currentHash], 0B09231BFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessToken:
    mov dword [currentHash], 0079A848Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenRegistryTransaction:
    mov dword [currentHash], 09A319AAFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenResourceManager:
    mov dword [currentHash], 0B66CDF77h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSemaphore:
    mov dword [currentHash], 0F6A700EFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSession:
    mov dword [currentHash], 00D814956h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSymbolicLinkObject:
    mov dword [currentHash], 01904FB1Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThread:
    mov dword [currentHash], 01A394106h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTimer:
    mov dword [currentHash], 0EFDDD16Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransaction:
    mov dword [currentHash], 005512406h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransactionManager:
    mov dword [currentHash], 075CB4D46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPlugPlayControl:
    mov dword [currentHash], 03DAA0509h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareComplete:
    mov dword [currentHash], 02CB80836h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareEnlistment:
    mov dword [currentHash], 0CBA5EC3Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareComplete:
    mov dword [currentHash], 036B3A4BCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareEnlistment:
    mov dword [currentHash], 009A70C2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeCheck:
    mov dword [currentHash], 0369A4D17h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeObjectAuditAlarm:
    mov dword [currentHash], 0E121E24Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegedServiceAuditAlarm:
    mov dword [currentHash], 018BE3C28h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationComplete:
    mov dword [currentHash], 0EC50B8DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationFailed:
    mov dword [currentHash], 03B967B3Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPulseEvent:
    mov dword [currentHash], 0B83B91A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAuxiliaryCounterFrequency:
    mov dword [currentHash], 02A98F7CCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootEntryOrder:
    mov dword [currentHash], 01F8FFB1Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootOptions:
    mov dword [currentHash], 03FA93D3Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDebugFilterState:
    mov dword [currentHash], 032B3381Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFileEx:
    mov dword [currentHash], 06A583A81h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryObject:
    mov dword [currentHash], 01E2038BDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDriverEntryOrder:
    mov dword [currentHash], 0030611A3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEaFile:
    mov dword [currentHash], 068B37000h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryFullAttributesFile:
    mov dword [currentHash], 05AC5645Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationAtom:
    mov dword [currentHash], 09602B592h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationByName:
    mov dword [currentHash], 0E70F1F6Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationEnlistment:
    mov dword [currentHash], 0264639ECh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationJobObject:
    mov dword [currentHash], 0C4592CC5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationPort:
    mov dword [currentHash], 0920FB59Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationResourceManager:
    mov dword [currentHash], 00FB2919Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransaction:
    mov dword [currentHash], 00C982C0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransactionManager:
    mov dword [currentHash], 0C7A72CDFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationWorkerFactory:
    mov dword [currentHash], 002921C16h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInstallUILanguage:
    mov dword [currentHash], 017B127EAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIntervalProfile:
    mov dword [currentHash], 0AC3DA4AEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIoCompletion:
    mov dword [currentHash], 0D44FD6DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryLicenseValue:
    mov dword [currentHash], 02C911B3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMultipleValueKey:
    mov dword [currentHash], 0AD19D0EAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMutant:
    mov dword [currentHash], 096B0913Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeys:
    mov dword [currentHash], 04BB626A8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeysEx:
    mov dword [currentHash], 0E319B7C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPortInformationProcess:
    mov dword [currentHash], 05F927806h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryQuotaInformationFile:
    mov dword [currentHash], 077C5FEE7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityAttributesToken:
    mov dword [currentHash], 07BDE4D76h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityObject:
    mov dword [currentHash], 090BFA0F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityPolicy:
    mov dword [currentHash], 0924491DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySemaphore:
    mov dword [currentHash], 0FD6197B7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySymbolicLinkObject:
    mov dword [currentHash], 095B8ABF2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValue:
    mov dword [currentHash], 0EEBB8F76h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValueEx:
    mov dword [currentHash], 0F7CCB537h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformationEx:
    mov dword [currentHash], 0AC916FCBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimerResolution:
    mov dword [currentHash], 00E952C59h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateData:
    mov dword [currentHash], 0BE05928Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateNameInformation:
    mov dword [currentHash], 084D362C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThreadEx:
    mov dword [currentHash], 0A0A0EE66h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseException:
    mov dword [currentHash], 006D2298Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseHardError:
    mov dword [currentHash], 003911D39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadOnlyEnlistment:
    mov dword [currentHash], 049C28E91h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverEnlistment:
    mov dword [currentHash], 09B359EA3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverResourceManager:
    mov dword [currentHash], 06E35F61Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverTransactionManager:
    mov dword [currentHash], 0042EDC04h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterProtocolAddressInformation:
    mov dword [currentHash], 0163F1CABh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterThreadTerminatePort:
    mov dword [currentHash], 0A23783AAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseKeyedEvent:
    mov dword [currentHash], 070C34B44h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseWorkerFactoryWorker:
    mov dword [currentHash], 0A4902D8Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletionEx:
    mov dword [currentHash], 09CAECE74h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveProcessDebug:
    mov dword [currentHash], 022BCCF36h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameKey:
    mov dword [currentHash], 0299D0C3Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameTransactionManager:
    mov dword [currentHash], 08E319293h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplaceKey:
    mov dword [currentHash], 0491C78A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplacePartitionUnit:
    mov dword [currentHash], 060B16C32h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReplyPort:
    mov dword [currentHash], 020B10F6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestPort:
    mov dword [currentHash], 05AB65B38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetEvent:
    mov dword [currentHash], 0EB51ECC2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetWriteWatch:
    mov dword [currentHash], 098D39446h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRestoreKey:
    mov dword [currentHash], 01BC3F6A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeProcess:
    mov dword [currentHash], 0419F7230h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRevertContainerImpersonation:
    mov dword [currentHash], 034A21431h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackComplete:
    mov dword [currentHash], 068B8741Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackEnlistment:
    mov dword [currentHash], 09136B2A1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackRegistryTransaction:
    mov dword [currentHash], 070BB5E67h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackTransaction:
    mov dword [currentHash], 01CF8004Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollforwardTransactionManager:
    mov dword [currentHash], 011C3410Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKey:
    mov dword [currentHash], 080016B6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKeyEx:
    mov dword [currentHash], 0EB6BDED6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveMergedKeys:
    mov dword [currentHash], 0D3B4D6C4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSecureConnectPort:
    mov dword [currentHash], 072ED4142h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSerializeBoot:
    mov dword [currentHash], 0B0207C61h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootEntryOrder:
    mov dword [currentHash], 0CDEFFD41h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootOptions:
    mov dword [currentHash], 09F099D9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel:
    mov dword [currentHash], 0CF7DE7A1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel2:
    mov dword [currentHash], 06EB2EC62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetContextThread:
    mov dword [currentHash], 04CFC0A5Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDebugFilterState:
    mov dword [currentHash], 0348E382Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultHardErrorPort:
    mov dword [currentHash], 0B8AAB528h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultLocale:
    mov dword [currentHash], 085A95D9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultUILanguage:
    mov dword [currentHash], 0AD325030h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDriverEntryOrder:
    mov dword [currentHash], 00F9C1D01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEaFile:
    mov dword [currentHash], 0533D3DE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighEventPair:
    mov dword [currentHash], 0A6AF463Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighWaitLowEventPair:
    mov dword [currentHash], 0A6B5AA27h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIRTimer:
    mov dword [currentHash], 0CD9D38FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationDebugObject:
    mov dword [currentHash], 018382487h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationEnlistment:
    mov dword [currentHash], 00B6410F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationJobObject:
    mov dword [currentHash], 01A25FA79h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationKey:
    mov dword [currentHash], 0F2C103B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationResourceManager:
    mov dword [currentHash], 031965B0Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationSymbolicLink:
    mov dword [currentHash], 0FAA72212h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationToken:
    mov dword [currentHash], 00386750Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransaction:
    mov dword [currentHash], 028823A2Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransactionManager:
    mov dword [currentHash], 0AB96218Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationVirtualMemory:
    mov dword [currentHash], 01B911D1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationWorkerFactory:
    mov dword [currentHash], 08A2290B6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIntervalProfile:
    mov dword [currentHash], 02581DD85h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletion:
    mov dword [currentHash], 002980237h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletionEx:
    mov dword [currentHash], 08CAEC268h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLdtEntries:
    mov dword [currentHash], 0FB53ECFBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowEventPair:
    mov dword [currentHash], 016B1CAE3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowWaitHighEventPair:
    mov dword [currentHash], 0F2D21640h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetQuotaInformationFile:
    mov dword [currentHash], 09706A793h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSecurityObject:
    mov dword [currentHash], 016B85055h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValue:
    mov dword [currentHash], 0C457E39Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValueEx:
    mov dword [currentHash], 037CBF2B6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemInformation:
    mov dword [currentHash], 0036F07FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemPowerState:
    mov dword [currentHash], 06C8F86C2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemTime:
    mov dword [currentHash], 08725CE82h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetThreadExecutionState:
    mov dword [currentHash], 0923D7C34h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer2:
    mov dword [currentHash], 079929A43h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerEx:
    mov dword [currentHash], 072E8ACBEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerResolution:
    mov dword [currentHash], 041146399h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetUuidSeed:
    mov dword [currentHash], 0D14ED7D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetVolumeInformationFile:
    mov dword [currentHash], 024B1D2A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetWnfProcessNotificationEvent:
    mov dword [currentHash], 0999D8030h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownSystem:
    mov dword [currentHash], 0D36EC9C1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownWorkerFactory:
    mov dword [currentHash], 0151D1594h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSignalAndWaitForSingleObject:
    mov dword [currentHash], 00AB43429h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSinglePhaseReject:
    mov dword [currentHash], 0745E2285h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartProfile:
    mov dword [currentHash], 058942A5Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStopProfile:
    mov dword [currentHash], 08F1B7843h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSubscribeWnfStateChange:
    mov dword [currentHash], 036A72F3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendProcess:
    mov dword [currentHash], 082C1834Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendThread:
    mov dword [currentHash], 07CDF2E69h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSystemDebugControl:
    mov dword [currentHash], 0D78BF51Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateEnclave:
    mov dword [currentHash], 04A8B16B2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateJobObject:
    mov dword [currentHash], 0188433DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTestAlert:
    mov dword [currentHash], 066379875h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawRegistry:
    mov dword [currentHash], 032A03229h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawTransactions:
    mov dword [currentHash], 0F144D313h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceControl:
    mov dword [currentHash], 00552E3C0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTranslateFilePath:
    mov dword [currentHash], 0873F6C6Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUmsThreadYield:
    mov dword [currentHash], 03FA60EF3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadDriver:
    mov dword [currentHash], 016B73BE8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey:
    mov dword [currentHash], 01A2F63DDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey2:
    mov dword [currentHash], 0C7350282h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKeyEx:
    mov dword [currentHash], 099F2AF4Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockFile:
    mov dword [currentHash], 03298E3D2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockVirtualMemory:
    mov dword [currentHash], 005966B01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSectionEx:
    mov dword [currentHash], 09B1D5659h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnsubscribeWnfStateChange:
    mov dword [currentHash], 082400D68h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUpdateWnfStateData:
    mov dword [currentHash], 062B9740Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtVdmControl:
    mov dword [currentHash], 05DB24511h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForAlertByThreadId:
    mov dword [currentHash], 09AAE3A6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForDebugEvent:
    mov dword [currentHash], 03E9BC0E9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForKeyedEvent:
    mov dword [currentHash], 0EB0AEA9Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWorkViaWorkerFactory:
    mov dword [currentHash], 0C091CA00h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitHighEventPair:
    mov dword [currentHash], 0219FDE96h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitLowEventPair:
    mov dword [currentHash], 0203804A9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireCMFViewOwnership:
    mov dword [currentHash], 0DA4C1D1Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelDeviceWakeupRequest:
    mov dword [currentHash], 073816522h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearAllSavepointsTransaction:
    mov dword [currentHash], 01A0E44C7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearSavepointTransaction:
    mov dword [currentHash], 0DCB3D223h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackSavepointTransaction:
    mov dword [currentHash], 0144F351Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointTransaction:
    mov dword [currentHash], 04CD76C19h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointComplete:
    mov dword [currentHash], 0009AF898h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSectionEx:
    mov dword [currentHash], 080953FB3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateCrossVmEvent:
    mov dword [currentHash], 01B2074B2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetPlugPlayEvent:
    mov dword [currentHash], 00E088D1Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListTransactions:
    mov dword [currentHash], 0B8299EB8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMarshallTransaction:
    mov dword [currentHash], 032A62A0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPullTransaction:
    mov dword [currentHash], 0040B2499h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseCMFViewOwnership:
    mov dword [currentHash], 034AD2036h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWnfNotifications:
    mov dword [currentHash], 05B896703h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartTm:
    mov dword [currentHash], 0D19DFE2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationProcess:
    mov dword [currentHash], 096288E47h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestDeviceWakeup:
    mov dword [currentHash], 02EA1223Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWakeupLatency:
    mov dword [currentHash], 0904BB1E6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemTime:
    mov dword [currentHash], 0B6AEC6BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManageHotPatch:
    mov dword [currentHash], 068A5287Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinueEx:
    mov dword [currentHash], 0D34D0411h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

RtlCreateUserThread:
    mov dword [currentHash], 0B4AF2B95h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

