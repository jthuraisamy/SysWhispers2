.intel_syntax noprefix
.data
currentHash:    .long   0

.text
.global NtAccessCheck
.global NtWorkerFactoryWorkerReady
.global NtAcceptConnectPort
.global NtMapUserPhysicalPagesScatter
.global NtWaitForSingleObject
.global NtCallbackReturn
.global NtReadFile
.global NtDeviceIoControlFile
.global NtWriteFile
.global NtRemoveIoCompletion
.global NtReleaseSemaphore
.global NtReplyWaitReceivePort
.global NtReplyPort
.global NtSetInformationThread
.global NtSetEvent
.global NtClose
.global NtQueryObject
.global NtQueryInformationFile
.global NtOpenKey
.global NtEnumerateValueKey
.global NtFindAtom
.global NtQueryDefaultLocale
.global NtQueryKey
.global NtQueryValueKey
.global NtAllocateVirtualMemory
.global NtQueryInformationProcess
.global NtWaitForMultipleObjects32
.global NtWriteFileGather
.global NtCreateKey
.global NtFreeVirtualMemory
.global NtImpersonateClientOfPort
.global NtReleaseMutant
.global NtQueryInformationToken
.global NtRequestWaitReplyPort
.global NtQueryVirtualMemory
.global NtOpenThreadToken
.global NtQueryInformationThread
.global NtOpenProcess
.global NtSetInformationFile
.global NtMapViewOfSection
.global NtAccessCheckAndAuditAlarm
.global NtUnmapViewOfSection
.global NtReplyWaitReceivePortEx
.global NtTerminateProcess
.global NtSetEventBoostPriority
.global NtReadFileScatter
.global NtOpenThreadTokenEx
.global NtOpenProcessTokenEx
.global NtQueryPerformanceCounter
.global NtEnumerateKey
.global NtOpenFile
.global NtDelayExecution
.global NtQueryDirectoryFile
.global NtQuerySystemInformation
.global NtOpenSection
.global NtQueryTimer
.global NtFsControlFile
.global NtWriteVirtualMemory
.global NtCloseObjectAuditAlarm
.global NtDuplicateObject
.global NtQueryAttributesFile
.global NtClearEvent
.global NtReadVirtualMemory
.global NtOpenEvent
.global NtAdjustPrivilegesToken
.global NtDuplicateToken
.global NtContinue
.global NtQueryDefaultUILanguage
.global NtQueueApcThread
.global NtYieldExecution
.global NtAddAtom
.global NtCreateEvent
.global NtQueryVolumeInformationFile
.global NtCreateSection
.global NtFlushBuffersFile
.global NtApphelpCacheControl
.global NtCreateProcessEx
.global NtCreateThread
.global NtIsProcessInJob
.global NtProtectVirtualMemory
.global NtQuerySection
.global NtResumeThread
.global NtTerminateThread
.global NtReadRequestData
.global NtCreateFile
.global NtQueryEvent
.global NtWriteRequestData
.global NtOpenDirectoryObject
.global NtAccessCheckByTypeAndAuditAlarm
.global NtWaitForMultipleObjects
.global NtSetInformationObject
.global NtCancelIoFile
.global NtTraceEvent
.global NtPowerInformation
.global NtSetValueKey
.global NtCancelTimer
.global NtSetTimer
.global NtAccessCheckByType
.global NtAccessCheckByTypeResultList
.global NtAccessCheckByTypeResultListAndAuditAlarm
.global NtAccessCheckByTypeResultListAndAuditAlarmByHandle
.global NtAcquireProcessActivityReference
.global NtAddAtomEx
.global NtAddBootEntry
.global NtAddDriverEntry
.global NtAdjustGroupsToken
.global NtAdjustTokenClaimsAndDeviceGroups
.global NtAlertResumeThread
.global NtAlertThread
.global NtAlertThreadByThreadId
.global NtAllocateLocallyUniqueId
.global NtAllocateReserveObject
.global NtAllocateUserPhysicalPages
.global NtAllocateUuids
.global NtAllocateVirtualMemoryEx
.global NtAlpcAcceptConnectPort
.global NtAlpcCancelMessage
.global NtAlpcConnectPort
.global NtAlpcConnectPortEx
.global NtAlpcCreatePort
.global NtAlpcCreatePortSection
.global NtAlpcCreateResourceReserve
.global NtAlpcCreateSectionView
.global NtAlpcCreateSecurityContext
.global NtAlpcDeletePortSection
.global NtAlpcDeleteResourceReserve
.global NtAlpcDeleteSectionView
.global NtAlpcDeleteSecurityContext
.global NtAlpcDisconnectPort
.global NtAlpcImpersonateClientContainerOfPort
.global NtAlpcImpersonateClientOfPort
.global NtAlpcOpenSenderProcess
.global NtAlpcOpenSenderThread
.global NtAlpcQueryInformation
.global NtAlpcQueryInformationMessage
.global NtAlpcRevokeSecurityContext
.global NtAlpcSendWaitReceivePort
.global NtAlpcSetInformation
.global NtAreMappedFilesTheSame
.global NtAssignProcessToJobObject
.global NtAssociateWaitCompletionPacket
.global NtCallEnclave
.global NtCancelIoFileEx
.global NtCancelSynchronousIoFile
.global NtCancelTimer2
.global NtCancelWaitCompletionPacket
.global NtCommitComplete
.global NtCommitEnlistment
.global NtCommitRegistryTransaction
.global NtCommitTransaction
.global NtCompactKeys
.global NtCompareObjects
.global NtCompareSigningLevels
.global NtCompareTokens
.global NtCompleteConnectPort
.global NtCompressKey
.global NtConnectPort
.global NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
.global NtCreateDebugObject
.global NtCreateDirectoryObject
.global NtCreateDirectoryObjectEx
.global NtCreateEnclave
.global NtCreateEnlistment
.global NtCreateEventPair
.global NtCreateIRTimer
.global NtCreateIoCompletion
.global NtCreateJobObject
.global NtCreateJobSet
.global NtCreateKeyTransacted
.global NtCreateKeyedEvent
.global NtCreateLowBoxToken
.global NtCreateMailslotFile
.global NtCreateMutant
.global NtCreateNamedPipeFile
.global NtCreatePagingFile
.global NtCreatePartition
.global NtCreatePort
.global NtCreatePrivateNamespace
.global NtCreateProcess
.global NtCreateProfile
.global NtCreateProfileEx
.global NtCreateRegistryTransaction
.global NtCreateResourceManager
.global NtCreateSemaphore
.global NtCreateSymbolicLinkObject
.global NtCreateThreadEx
.global NtCreateTimer
.global NtCreateTimer2
.global NtCreateToken
.global NtCreateTokenEx
.global NtCreateTransaction
.global NtCreateTransactionManager
.global NtCreateUserProcess
.global NtCreateWaitCompletionPacket
.global NtCreateWaitablePort
.global NtCreateWnfStateName
.global NtCreateWorkerFactory
.global NtDebugActiveProcess
.global NtDebugContinue
.global NtDeleteAtom
.global NtDeleteBootEntry
.global NtDeleteDriverEntry
.global NtDeleteFile
.global NtDeleteKey
.global NtDeleteObjectAuditAlarm
.global NtDeletePrivateNamespace
.global NtDeleteValueKey
.global NtDeleteWnfStateData
.global NtDeleteWnfStateName
.global NtDisableLastKnownGood
.global NtDisplayString
.global NtDrawText
.global NtEnableLastKnownGood
.global NtEnumerateBootEntries
.global NtEnumerateDriverEntries
.global NtEnumerateSystemEnvironmentValuesEx
.global NtEnumerateTransactionObject
.global NtExtendSection
.global NtFilterBootOption
.global NtFilterToken
.global NtFilterTokenEx
.global NtFlushBuffersFileEx
.global NtFlushInstallUILanguage
.global NtFlushInstructionCache
.global NtFlushKey
.global NtFlushProcessWriteBuffers
.global NtFlushVirtualMemory
.global NtFlushWriteBuffer
.global NtFreeUserPhysicalPages
.global NtFreezeRegistry
.global NtFreezeTransactions
.global NtGetCachedSigningLevel
.global NtGetCompleteWnfStateSubscription
.global NtGetContextThread
.global NtGetCurrentProcessorNumber
.global NtGetCurrentProcessorNumberEx
.global NtGetDevicePowerState
.global NtGetMUIRegistryInfo
.global NtGetNextProcess
.global NtGetNextThread
.global NtGetNlsSectionPtr
.global NtGetNotificationResourceManager
.global NtGetWriteWatch
.global NtImpersonateAnonymousToken
.global NtImpersonateThread
.global NtInitializeEnclave
.global NtInitializeNlsFiles
.global NtInitializeRegistry
.global NtInitiatePowerAction
.global NtIsSystemResumeAutomatic
.global NtIsUILanguageComitted
.global NtListenPort
.global NtLoadDriver
.global NtLoadEnclaveData
.global NtLoadHotPatch
.global NtLoadKey
.global NtLoadKey2
.global NtLoadKeyEx
.global NtLockFile
.global NtLockProductActivationKeys
.global NtLockRegistryKey
.global NtLockVirtualMemory
.global NtMakePermanentObject
.global NtMakeTemporaryObject
.global NtManagePartition
.global NtMapCMFModule
.global NtMapUserPhysicalPages
.global NtMapViewOfSectionEx
.global NtModifyBootEntry
.global NtModifyDriverEntry
.global NtNotifyChangeDirectoryFile
.global NtNotifyChangeDirectoryFileEx
.global NtNotifyChangeKey
.global NtNotifyChangeMultipleKeys
.global NtNotifyChangeSession
.global NtOpenEnlistment
.global NtOpenEventPair
.global NtOpenIoCompletion
.global NtOpenJobObject
.global NtOpenKeyEx
.global NtOpenKeyTransacted
.global NtOpenKeyTransactedEx
.global NtOpenKeyedEvent
.global NtOpenMutant
.global NtOpenObjectAuditAlarm
.global NtOpenPartition
.global NtOpenPrivateNamespace
.global NtOpenProcessToken
.global NtOpenRegistryTransaction
.global NtOpenResourceManager
.global NtOpenSemaphore
.global NtOpenSession
.global NtOpenSymbolicLinkObject
.global NtOpenThread
.global NtOpenTimer
.global NtOpenTransaction
.global NtOpenTransactionManager
.global NtPlugPlayControl
.global NtPrePrepareComplete
.global NtPrePrepareEnlistment
.global NtPrepareComplete
.global NtPrepareEnlistment
.global NtPrivilegeCheck
.global NtPrivilegeObjectAuditAlarm
.global NtPrivilegedServiceAuditAlarm
.global NtPropagationComplete
.global NtPropagationFailed
.global NtPulseEvent
.global NtQueryAuxiliaryCounterFrequency
.global NtQueryBootEntryOrder
.global NtQueryBootOptions
.global NtQueryDebugFilterState
.global NtQueryDirectoryFileEx
.global NtQueryDirectoryObject
.global NtQueryDriverEntryOrder
.global NtQueryEaFile
.global NtQueryFullAttributesFile
.global NtQueryInformationAtom
.global NtQueryInformationByName
.global NtQueryInformationEnlistment
.global NtQueryInformationJobObject
.global NtQueryInformationPort
.global NtQueryInformationResourceManager
.global NtQueryInformationTransaction
.global NtQueryInformationTransactionManager
.global NtQueryInformationWorkerFactory
.global NtQueryInstallUILanguage
.global NtQueryIntervalProfile
.global NtQueryIoCompletion
.global NtQueryLicenseValue
.global NtQueryMultipleValueKey
.global NtQueryMutant
.global NtQueryOpenSubKeys
.global NtQueryOpenSubKeysEx
.global NtQueryPortInformationProcess
.global NtQueryQuotaInformationFile
.global NtQuerySecurityAttributesToken
.global NtQuerySecurityObject
.global NtQuerySecurityPolicy
.global NtQuerySemaphore
.global NtQuerySymbolicLinkObject
.global NtQuerySystemEnvironmentValue
.global NtQuerySystemEnvironmentValueEx
.global NtQuerySystemInformationEx
.global NtQueryTimerResolution
.global NtQueryWnfStateData
.global NtQueryWnfStateNameInformation
.global NtQueueApcThreadEx
.global NtRaiseException
.global NtRaiseHardError
.global NtReadOnlyEnlistment
.global NtRecoverEnlistment
.global NtRecoverResourceManager
.global NtRecoverTransactionManager
.global NtRegisterProtocolAddressInformation
.global NtRegisterThreadTerminatePort
.global NtReleaseKeyedEvent
.global NtReleaseWorkerFactoryWorker
.global NtRemoveIoCompletionEx
.global NtRemoveProcessDebug
.global NtRenameKey
.global NtRenameTransactionManager
.global NtReplaceKey
.global NtReplacePartitionUnit
.global NtReplyWaitReplyPort
.global NtRequestPort
.global NtResetEvent
.global NtResetWriteWatch
.global NtRestoreKey
.global NtResumeProcess
.global NtRevertContainerImpersonation
.global NtRollbackComplete
.global NtRollbackEnlistment
.global NtRollbackRegistryTransaction
.global NtRollbackTransaction
.global NtRollforwardTransactionManager
.global NtSaveKey
.global NtSaveKeyEx
.global NtSaveMergedKeys
.global NtSecureConnectPort
.global NtSerializeBoot
.global NtSetBootEntryOrder
.global NtSetBootOptions
.global NtSetCachedSigningLevel
.global NtSetCachedSigningLevel2
.global NtSetContextThread
.global NtSetDebugFilterState
.global NtSetDefaultHardErrorPort
.global NtSetDefaultLocale
.global NtSetDefaultUILanguage
.global NtSetDriverEntryOrder
.global NtSetEaFile
.global NtSetHighEventPair
.global NtSetHighWaitLowEventPair
.global NtSetIRTimer
.global NtSetInformationDebugObject
.global NtSetInformationEnlistment
.global NtSetInformationJobObject
.global NtSetInformationKey
.global NtSetInformationResourceManager
.global NtSetInformationSymbolicLink
.global NtSetInformationToken
.global NtSetInformationTransaction
.global NtSetInformationTransactionManager
.global NtSetInformationVirtualMemory
.global NtSetInformationWorkerFactory
.global NtSetIntervalProfile
.global NtSetIoCompletion
.global NtSetIoCompletionEx
.global NtSetLdtEntries
.global NtSetLowEventPair
.global NtSetLowWaitHighEventPair
.global NtSetQuotaInformationFile
.global NtSetSecurityObject
.global NtSetSystemEnvironmentValue
.global NtSetSystemEnvironmentValueEx
.global NtSetSystemInformation
.global NtSetSystemPowerState
.global NtSetSystemTime
.global NtSetThreadExecutionState
.global NtSetTimer2
.global NtSetTimerEx
.global NtSetTimerResolution
.global NtSetUuidSeed
.global NtSetVolumeInformationFile
.global NtSetWnfProcessNotificationEvent
.global NtShutdownSystem
.global NtShutdownWorkerFactory
.global NtSignalAndWaitForSingleObject
.global NtSinglePhaseReject
.global NtStartProfile
.global NtStopProfile
.global NtSubscribeWnfStateChange
.global NtSuspendProcess
.global NtSuspendThread
.global NtSystemDebugControl
.global NtTerminateEnclave
.global NtTerminateJobObject
.global NtTestAlert
.global NtThawRegistry
.global NtThawTransactions
.global NtTraceControl
.global NtTranslateFilePath
.global NtUmsThreadYield
.global NtUnloadDriver
.global NtUnloadKey
.global NtUnloadKey2
.global NtUnloadKeyEx
.global NtUnlockFile
.global NtUnlockVirtualMemory
.global NtUnmapViewOfSectionEx
.global NtUnsubscribeWnfStateChange
.global NtUpdateWnfStateData
.global NtVdmControl
.global NtWaitForAlertByThreadId
.global NtWaitForDebugEvent
.global NtWaitForKeyedEvent
.global NtWaitForWorkViaWorkerFactory
.global NtWaitHighEventPair
.global NtWaitLowEventPair
.global NtAcquireCMFViewOwnership
.global NtCancelDeviceWakeupRequest
.global NtClearAllSavepointsTransaction
.global NtClearSavepointTransaction
.global NtRollbackSavepointTransaction
.global NtSavepointTransaction
.global NtSavepointComplete
.global NtCreateSectionEx
.global NtCreateCrossVmEvent
.global NtGetPlugPlayEvent
.global NtListTransactions
.global NtMarshallTransaction
.global NtPullTransaction
.global NtReleaseCMFViewOwnership
.global NtWaitForWnfNotifications
.global NtStartTm
.global NtSetInformationProcess
.global NtRequestDeviceWakeup
.global NtRequestWakeupLatency
.global NtQuerySystemTime
.global NtManageHotPatch
.global NtContinueEx
.global RtlCreateUserThread

.global WhisperMain
.extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash]
    call SW2_GetSyscallNumber
    add rsp, 0x28
    mov rcx, [rsp+ 8]              # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        # Issue syscall
    ret

NtAccessCheck:
    mov dword ptr [currentHash], 0x0FA40F4F9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWorkerFactoryWorkerReady:
    mov dword ptr [currentHash], 0x011A63B35   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcceptConnectPort:
    mov dword ptr [currentHash], 0x064F17B62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPagesScatter:
    mov dword ptr [currentHash], 0x0238A0D17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForSingleObject:
    mov dword ptr [currentHash], 0x0009E3E33   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallbackReturn:
    mov dword ptr [currentHash], 0x0168C371A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFile:
    mov dword ptr [currentHash], 0x0C544CDF1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeviceIoControlFile:
    mov dword ptr [currentHash], 0x022342AD2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFile:
    mov dword ptr [currentHash], 0x0E97AEB1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletion:
    mov dword ptr [currentHash], 0x0088E0821   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseSemaphore:
    mov dword ptr [currentHash], 0x034A10CFC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePort:
    mov dword ptr [currentHash], 0x0ACFE8EA0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyPort:
    mov dword ptr [currentHash], 0x062B0692E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationThread:
    mov dword ptr [currentHash], 0x00A2E4E86   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEvent:
    mov dword ptr [currentHash], 0x058924AF4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClose:
    mov dword ptr [currentHash], 0x00352369D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryObject:
    mov dword ptr [currentHash], 0x08CA077CC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationFile:
    mov dword ptr [currentHash], 0x0A635B086   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKey:
    mov dword ptr [currentHash], 0x00F1A54C7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateValueKey:
    mov dword ptr [currentHash], 0x016AB2319   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFindAtom:
    mov dword ptr [currentHash], 0x03565D433   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultLocale:
    mov dword ptr [currentHash], 0x0025D728B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryKey:
    mov dword ptr [currentHash], 0x008172BAC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryValueKey:
    mov dword ptr [currentHash], 0x0E15C142E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemory:
    mov dword ptr [currentHash], 0x01F88E9E7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationProcess:
    mov dword ptr [currentHash], 0x0D99B2213   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects32:
    mov dword ptr [currentHash], 0x08E9DAF4A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFileGather:
    mov dword ptr [currentHash], 0x02B907B53   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKey:
    mov dword ptr [currentHash], 0x07EC9073B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeVirtualMemory:
    mov dword ptr [currentHash], 0x0099E0519   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateClientOfPort:
    mov dword ptr [currentHash], 0x060F36F68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseMutant:
    mov dword ptr [currentHash], 0x02D4A0AD0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationToken:
    mov dword ptr [currentHash], 0x035AA1F32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWaitReplyPort:
    mov dword ptr [currentHash], 0x0E273D9DC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVirtualMemory:
    mov dword ptr [currentHash], 0x09514A39B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadToken:
    mov dword ptr [currentHash], 0x0F8512DEA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationThread:
    mov dword ptr [currentHash], 0x024881E11   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcess:
    mov dword ptr [currentHash], 0x006AC0521   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationFile:
    mov dword ptr [currentHash], 0x0CA7AC2EC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSection:
    mov dword ptr [currentHash], 0x004960E0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckAndAuditAlarm:
    mov dword ptr [currentHash], 0x00F2EC371   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSection:
    mov dword ptr [currentHash], 0x0568C3591   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePortEx:
    mov dword ptr [currentHash], 0x0A25FEA98   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateProcess:
    mov dword ptr [currentHash], 0x0FE26D5BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEventBoostPriority:
    mov dword ptr [currentHash], 0x030863C0C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFileScatter:
    mov dword ptr [currentHash], 0x0159C1D07   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadTokenEx:
    mov dword ptr [currentHash], 0x02FBAF2EF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessTokenEx:
    mov dword ptr [currentHash], 0x0791FB957   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPerformanceCounter:
    mov dword ptr [currentHash], 0x037D24B39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateKey:
    mov dword ptr [currentHash], 0x0B6AE97F4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenFile:
    mov dword ptr [currentHash], 0x0AD1C2B01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDelayExecution:
    mov dword ptr [currentHash], 0x0520D529F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFile:
    mov dword ptr [currentHash], 0x058BBAAE2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformation:
    mov dword ptr [currentHash], 0x054CD765D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSection:
    mov dword ptr [currentHash], 0x00A9E284F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimer:
    mov dword ptr [currentHash], 0x0179F7F46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFsControlFile:
    mov dword ptr [currentHash], 0x06AF45662   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteVirtualMemory:
    mov dword ptr [currentHash], 0x005953B23   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCloseObjectAuditAlarm:
    mov dword ptr [currentHash], 0x05CDA584C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateObject:
    mov dword ptr [currentHash], 0x03EA1F6FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAttributesFile:
    mov dword ptr [currentHash], 0x0DD5DD9FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearEvent:
    mov dword ptr [currentHash], 0x0200B65DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadVirtualMemory:
    mov dword ptr [currentHash], 0x0071473E9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEvent:
    mov dword ptr [currentHash], 0x030D52978   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustPrivilegesToken:
    mov dword ptr [currentHash], 0x001940B2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateToken:
    mov dword ptr [currentHash], 0x06DD92558   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinue:
    mov dword ptr [currentHash], 0x0009CD3D0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultUILanguage:
    mov dword ptr [currentHash], 0x013C5D178   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThread:
    mov dword ptr [currentHash], 0x02E8A0C2B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtYieldExecution:
    mov dword ptr [currentHash], 0x014B63E33   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtom:
    mov dword ptr [currentHash], 0x022BF272E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEvent:
    mov dword ptr [currentHash], 0x0B0B4AF3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVolumeInformationFile:
    mov dword ptr [currentHash], 0x0E5B3BD76   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSection:
    mov dword ptr [currentHash], 0x04EC54C51   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFile:
    mov dword ptr [currentHash], 0x06CFB5E2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtApphelpCacheControl:
    mov dword ptr [currentHash], 0x0FD6DDFBB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcessEx:
    mov dword ptr [currentHash], 0x0B998FB42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThread:
    mov dword ptr [currentHash], 0x0AF8CB334   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsProcessInJob:
    mov dword ptr [currentHash], 0x05CE54854   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtProtectVirtualMemory:
    mov dword ptr [currentHash], 0x00F940311   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySection:
    mov dword ptr [currentHash], 0x002EC25B9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeThread:
    mov dword ptr [currentHash], 0x07D5445CF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateThread:
    mov dword ptr [currentHash], 0x0228E3037   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadRequestData:
    mov dword ptr [currentHash], 0x0A23EB14C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateFile:
    mov dword ptr [currentHash], 0x02A9AE32E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEvent:
    mov dword ptr [currentHash], 0x02AB1F0E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteRequestData:
    mov dword ptr [currentHash], 0x09DC08975   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenDirectoryObject:
    mov dword ptr [currentHash], 0x03C802E0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeAndAuditAlarm:
    mov dword ptr [currentHash], 0x0DD42B9D5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects:
    mov dword ptr [currentHash], 0x061AD6331   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationObject:
    mov dword ptr [currentHash], 0x0271915A7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFile:
    mov dword ptr [currentHash], 0x0821B7543   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceEvent:
    mov dword ptr [currentHash], 0x0CAED7BD0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPowerInformation:
    mov dword ptr [currentHash], 0x054C25A5F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetValueKey:
    mov dword ptr [currentHash], 0x01DC11E58   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer:
    mov dword ptr [currentHash], 0x001A23302   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer:
    mov dword ptr [currentHash], 0x005977F7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByType:
    mov dword ptr [currentHash], 0x0D442E30A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultList:
    mov dword ptr [currentHash], 0x07EA17221   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword ptr [currentHash], 0x0552A6982   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword ptr [currentHash], 0x099B41796   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireProcessActivityReference:
    mov dword ptr [currentHash], 0x01A8958A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtomEx:
    mov dword ptr [currentHash], 0x09390C74C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddBootEntry:
    mov dword ptr [currentHash], 0x005951912   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddDriverEntry:
    mov dword ptr [currentHash], 0x03B67B174   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustGroupsToken:
    mov dword ptr [currentHash], 0x025971314   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustTokenClaimsAndDeviceGroups:
    mov dword ptr [currentHash], 0x007900309   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertResumeThread:
    mov dword ptr [currentHash], 0x0A48BA81A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThread:
    mov dword ptr [currentHash], 0x01CA4540B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThreadByThreadId:
    mov dword ptr [currentHash], 0x0B8A26896   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateLocallyUniqueId:
    mov dword ptr [currentHash], 0x0FFE51B65   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateReserveObject:
    mov dword ptr [currentHash], 0x018B4E6C9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUserPhysicalPages:
    mov dword ptr [currentHash], 0x019BF3A24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUuids:
    mov dword ptr [currentHash], 0x0338FFDD3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemoryEx:
    mov dword ptr [currentHash], 0x0C8503B3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcAcceptConnectPort:
    mov dword ptr [currentHash], 0x030B2213C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCancelMessage:
    mov dword ptr [currentHash], 0x073D77E7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPort:
    mov dword ptr [currentHash], 0x03EB1DDDE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPortEx:
    mov dword ptr [currentHash], 0x0636DBF29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePort:
    mov dword ptr [currentHash], 0x0194B9F58   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePortSection:
    mov dword ptr [currentHash], 0x0C4F5DE41   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateResourceReserve:
    mov dword ptr [currentHash], 0x0389F4A77   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSectionView:
    mov dword ptr [currentHash], 0x02CA81D13   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSecurityContext:
    mov dword ptr [currentHash], 0x0FA1DE794   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeletePortSection:
    mov dword ptr [currentHash], 0x00C982C0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteResourceReserve:
    mov dword ptr [currentHash], 0x01888F4C3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSectionView:
    mov dword ptr [currentHash], 0x056EC6753   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSecurityContext:
    mov dword ptr [currentHash], 0x008B3EDDA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDisconnectPort:
    mov dword ptr [currentHash], 0x022B5D93A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientContainerOfPort:
    mov dword ptr [currentHash], 0x02233A722   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientOfPort:
    mov dword ptr [currentHash], 0x0D836C9DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderProcess:
    mov dword ptr [currentHash], 0x0C654C5C9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderThread:
    mov dword ptr [currentHash], 0x0F85F36ED   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformation:
    mov dword ptr [currentHash], 0x0024618CE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformationMessage:
    mov dword ptr [currentHash], 0x0A40091AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcRevokeSecurityContext:
    mov dword ptr [currentHash], 0x040998DC8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSendWaitReceivePort:
    mov dword ptr [currentHash], 0x022B2A5B8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSetInformation:
    mov dword ptr [currentHash], 0x0C897E64B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAreMappedFilesTheSame:
    mov dword ptr [currentHash], 0x0D65AEDFD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssignProcessToJobObject:
    mov dword ptr [currentHash], 0x0FF2A6100   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssociateWaitCompletionPacket:
    mov dword ptr [currentHash], 0x007B22910   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallEnclave:
    mov dword ptr [currentHash], 0x08736BB65   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFileEx:
    mov dword ptr [currentHash], 0x0F758392D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelSynchronousIoFile:
    mov dword ptr [currentHash], 0x0256033EA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer2:
    mov dword ptr [currentHash], 0x003A35E2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelWaitCompletionPacket:
    mov dword ptr [currentHash], 0x0BC9C9AC6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitComplete:
    mov dword ptr [currentHash], 0x00C9007FE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitEnlistment:
    mov dword ptr [currentHash], 0x0164B0FC6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitRegistryTransaction:
    mov dword ptr [currentHash], 0x004B43E31   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitTransaction:
    mov dword ptr [currentHash], 0x018813A51   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompactKeys:
    mov dword ptr [currentHash], 0x057BA6A14   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareObjects:
    mov dword ptr [currentHash], 0x084648AF6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareSigningLevels:
    mov dword ptr [currentHash], 0x0AEF09E73   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareTokens:
    mov dword ptr [currentHash], 0x0F494EC01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompleteConnectPort:
    mov dword ptr [currentHash], 0x03A7637F8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompressKey:
    mov dword ptr [currentHash], 0x0782E5F8E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConnectPort:
    mov dword ptr [currentHash], 0x0A23C9072   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword ptr [currentHash], 0x079468945   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDebugObject:
    mov dword ptr [currentHash], 0x0009E21C3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObject:
    mov dword ptr [currentHash], 0x0FAD436BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObjectEx:
    mov dword ptr [currentHash], 0x0426E10B4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnclave:
    mov dword ptr [currentHash], 0x0CA2FDE86   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnlistment:
    mov dword ptr [currentHash], 0x00F90ECC7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEventPair:
    mov dword ptr [currentHash], 0x012B1CCFC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIRTimer:
    mov dword ptr [currentHash], 0x0178C3F36   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIoCompletion:
    mov dword ptr [currentHash], 0x00E1750D7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobObject:
    mov dword ptr [currentHash], 0x0F65B6E57   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobSet:
    mov dword ptr [currentHash], 0x08740AF1C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyTransacted:
    mov dword ptr [currentHash], 0x0A69A66C6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyedEvent:
    mov dword ptr [currentHash], 0x068CF755E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateLowBoxToken:
    mov dword ptr [currentHash], 0x017C73D1C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMailslotFile:
    mov dword ptr [currentHash], 0x0E47DC2FE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMutant:
    mov dword ptr [currentHash], 0x0FDDC08A5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateNamedPipeFile:
    mov dword ptr [currentHash], 0x0ED7AA75B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePagingFile:
    mov dword ptr [currentHash], 0x054C36C00   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePartition:
    mov dword ptr [currentHash], 0x0444E255D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePort:
    mov dword ptr [currentHash], 0x02EB4CCDA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePrivateNamespace:
    mov dword ptr [currentHash], 0x009B1CFEB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcess:
    mov dword ptr [currentHash], 0x081288EB0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfile:
    mov dword ptr [currentHash], 0x06E3E6AA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfileEx:
    mov dword ptr [currentHash], 0x0029AC0C1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateRegistryTransaction:
    mov dword ptr [currentHash], 0x0970FD3DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateResourceManager:
    mov dword ptr [currentHash], 0x06E52FA4F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSemaphore:
    mov dword ptr [currentHash], 0x0FCB62D1A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSymbolicLinkObject:
    mov dword ptr [currentHash], 0x083189384   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThreadEx:
    mov dword ptr [currentHash], 0x096A7CC64   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer:
    mov dword ptr [currentHash], 0x0E58D8F55   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer2:
    mov dword ptr [currentHash], 0x0B0684CA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateToken:
    mov dword ptr [currentHash], 0x0099F9FBF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTokenEx:
    mov dword ptr [currentHash], 0x06022A67C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransaction:
    mov dword ptr [currentHash], 0x03CEE2243   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransactionManager:
    mov dword ptr [currentHash], 0x01BA730FA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateUserProcess:
    mov dword ptr [currentHash], 0x0EC26CFBB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitCompletionPacket:
    mov dword ptr [currentHash], 0x001813F0A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitablePort:
    mov dword ptr [currentHash], 0x0A97288DF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWnfStateName:
    mov dword ptr [currentHash], 0x0CED0FB42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWorkerFactory:
    mov dword ptr [currentHash], 0x0089C140A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugActiveProcess:
    mov dword ptr [currentHash], 0x0923099AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugContinue:
    mov dword ptr [currentHash], 0x05D24BC68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteAtom:
    mov dword ptr [currentHash], 0x0BED35C8B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteBootEntry:
    mov dword ptr [currentHash], 0x0336B3BE4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteDriverEntry:
    mov dword ptr [currentHash], 0x033930B14   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteFile:
    mov dword ptr [currentHash], 0x06EF46592   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteKey:
    mov dword ptr [currentHash], 0x03AEE1D71   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteObjectAuditAlarm:
    mov dword ptr [currentHash], 0x016B57464   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeletePrivateNamespace:
    mov dword ptr [currentHash], 0x02A88393F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteValueKey:
    mov dword ptr [currentHash], 0x036820931   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateData:
    mov dword ptr [currentHash], 0x032CE441A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateName:
    mov dword ptr [currentHash], 0x0A8B02387   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisableLastKnownGood:
    mov dword ptr [currentHash], 0x0386B35C2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisplayString:
    mov dword ptr [currentHash], 0x076E83238   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDrawText:
    mov dword ptr [currentHash], 0x04918735E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnableLastKnownGood:
    mov dword ptr [currentHash], 0x02DBE03F4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateBootEntries:
    mov dword ptr [currentHash], 0x02C97BD9B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateDriverEntries:
    mov dword ptr [currentHash], 0x07CDC2D7F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateSystemEnvironmentValuesEx:
    mov dword ptr [currentHash], 0x053AF8FFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateTransactionObject:
    mov dword ptr [currentHash], 0x096B4A608   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtExtendSection:
    mov dword ptr [currentHash], 0x00E8A340F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterBootOption:
    mov dword ptr [currentHash], 0x008A20BCF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterToken:
    mov dword ptr [currentHash], 0x07FD56972   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterTokenEx:
    mov dword ptr [currentHash], 0x08E59B5DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFileEx:
    mov dword ptr [currentHash], 0x026D4E08A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstallUILanguage:
    mov dword ptr [currentHash], 0x0A5BAD1A1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstructionCache:
    mov dword ptr [currentHash], 0x00DAE4997   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushKey:
    mov dword ptr [currentHash], 0x09ED4BF6E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushProcessWriteBuffers:
    mov dword ptr [currentHash], 0x0D83A3DA2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushVirtualMemory:
    mov dword ptr [currentHash], 0x08713938F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushWriteBuffer:
    mov dword ptr [currentHash], 0x0A538B5A7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeUserPhysicalPages:
    mov dword ptr [currentHash], 0x0E5BEEE26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeRegistry:
    mov dword ptr [currentHash], 0x0069B203B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeTransactions:
    mov dword ptr [currentHash], 0x04FAA257D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCachedSigningLevel:
    mov dword ptr [currentHash], 0x076BCA01E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCompleteWnfStateSubscription:
    mov dword ptr [currentHash], 0x0148F1A13   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetContextThread:
    mov dword ptr [currentHash], 0x00C9C1E2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumber:
    mov dword ptr [currentHash], 0x08E33C8E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumberEx:
    mov dword ptr [currentHash], 0x05AD599AE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetDevicePowerState:
    mov dword ptr [currentHash], 0x0A43BB4B4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetMUIRegistryInfo:
    mov dword ptr [currentHash], 0x07ACEA663   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextProcess:
    mov dword ptr [currentHash], 0x00DA3362C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextThread:
    mov dword ptr [currentHash], 0x09A3DD48F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNlsSectionPtr:
    mov dword ptr [currentHash], 0x0FF5DD282   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNotificationResourceManager:
    mov dword ptr [currentHash], 0x0EFB2719E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetWriteWatch:
    mov dword ptr [currentHash], 0x08AA31383   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateAnonymousToken:
    mov dword ptr [currentHash], 0x03F8F0F22   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateThread:
    mov dword ptr [currentHash], 0x0FA202799   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeEnclave:
    mov dword ptr [currentHash], 0x02C9310D2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeNlsFiles:
    mov dword ptr [currentHash], 0x0744F05AC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeRegistry:
    mov dword ptr [currentHash], 0x034901C3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitiatePowerAction:
    mov dword ptr [currentHash], 0x0C690DF3B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsSystemResumeAutomatic:
    mov dword ptr [currentHash], 0x0A4A02186   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsUILanguageComitted:
    mov dword ptr [currentHash], 0x0D5EB91C3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListenPort:
    mov dword ptr [currentHash], 0x0DCB0DF3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadDriver:
    mov dword ptr [currentHash], 0x01C9F4E5C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadEnclaveData:
    mov dword ptr [currentHash], 0x0074E907A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadHotPatch:
    mov dword ptr [currentHash], 0x09F721D4F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey:
    mov dword ptr [currentHash], 0x03F1844E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey2:
    mov dword ptr [currentHash], 0x0DA270AA1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKeyEx:
    mov dword ptr [currentHash], 0x0BBFD8746   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockFile:
    mov dword ptr [currentHash], 0x0E17FCDAF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockProductActivationKeys:
    mov dword ptr [currentHash], 0x067E66A7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockRegistryKey:
    mov dword ptr [currentHash], 0x0130628B6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockVirtualMemory:
    mov dword ptr [currentHash], 0x00B981D77   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakePermanentObject:
    mov dword ptr [currentHash], 0x0243B2EA5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakeTemporaryObject:
    mov dword ptr [currentHash], 0x0263B5ED7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManagePartition:
    mov dword ptr [currentHash], 0x008B1E6ED   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapCMFModule:
    mov dword ptr [currentHash], 0x03917A320   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPages:
    mov dword ptr [currentHash], 0x01142E82C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSectionEx:
    mov dword ptr [currentHash], 0x0BE9CE842   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyBootEntry:
    mov dword ptr [currentHash], 0x009941D38   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyDriverEntry:
    mov dword ptr [currentHash], 0x071E16D64   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFile:
    mov dword ptr [currentHash], 0x01999E00D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFileEx:
    mov dword ptr [currentHash], 0x06B97BFCB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeKey:
    mov dword ptr [currentHash], 0x0CB12AAE8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeMultipleKeys:
    mov dword ptr [currentHash], 0x07F837404   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeSession:
    mov dword ptr [currentHash], 0x0E78FE71D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEnlistment:
    mov dword ptr [currentHash], 0x0BABADD51   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEventPair:
    mov dword ptr [currentHash], 0x090B047E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenIoCompletion:
    mov dword ptr [currentHash], 0x00C656AAD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenJobObject:
    mov dword ptr [currentHash], 0x0429C0E63   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyEx:
    mov dword ptr [currentHash], 0x06BDD9BA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransacted:
    mov dword ptr [currentHash], 0x010CD1A62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransactedEx:
    mov dword ptr [currentHash], 0x086AEC878   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyedEvent:
    mov dword ptr [currentHash], 0x050CB5D4A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenMutant:
    mov dword ptr [currentHash], 0x01693FCC5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenObjectAuditAlarm:
    mov dword ptr [currentHash], 0x074B25FF4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPartition:
    mov dword ptr [currentHash], 0x00ABA2FF1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPrivateNamespace:
    mov dword ptr [currentHash], 0x0B09231BF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessToken:
    mov dword ptr [currentHash], 0x0079A848B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenRegistryTransaction:
    mov dword ptr [currentHash], 0x09A319AAF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenResourceManager:
    mov dword ptr [currentHash], 0x0B66CDF77   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSemaphore:
    mov dword ptr [currentHash], 0x0F6A700EF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSession:
    mov dword ptr [currentHash], 0x00D814956   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSymbolicLinkObject:
    mov dword ptr [currentHash], 0x01904FB1A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThread:
    mov dword ptr [currentHash], 0x01A394106   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTimer:
    mov dword ptr [currentHash], 0x0EFDDD16C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransaction:
    mov dword ptr [currentHash], 0x005512406   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransactionManager:
    mov dword ptr [currentHash], 0x075CB4D46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPlugPlayControl:
    mov dword ptr [currentHash], 0x03DAA0509   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareComplete:
    mov dword ptr [currentHash], 0x02CB80836   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareEnlistment:
    mov dword ptr [currentHash], 0x0CBA5EC3E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareComplete:
    mov dword ptr [currentHash], 0x036B3A4BC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareEnlistment:
    mov dword ptr [currentHash], 0x009A70C2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeCheck:
    mov dword ptr [currentHash], 0x0369A4D17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeObjectAuditAlarm:
    mov dword ptr [currentHash], 0x0E121E24F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegedServiceAuditAlarm:
    mov dword ptr [currentHash], 0x018BE3C28   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationComplete:
    mov dword ptr [currentHash], 0x0EC50B8DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationFailed:
    mov dword ptr [currentHash], 0x03B967B3D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPulseEvent:
    mov dword ptr [currentHash], 0x0B83B91A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAuxiliaryCounterFrequency:
    mov dword ptr [currentHash], 0x02A98F7CC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootEntryOrder:
    mov dword ptr [currentHash], 0x01F8FFB1D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootOptions:
    mov dword ptr [currentHash], 0x03FA93D3D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDebugFilterState:
    mov dword ptr [currentHash], 0x032B3381C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFileEx:
    mov dword ptr [currentHash], 0x06A583A81   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryObject:
    mov dword ptr [currentHash], 0x01E2038BD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDriverEntryOrder:
    mov dword ptr [currentHash], 0x0030611A3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEaFile:
    mov dword ptr [currentHash], 0x068B37000   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryFullAttributesFile:
    mov dword ptr [currentHash], 0x05AC5645E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationAtom:
    mov dword ptr [currentHash], 0x09602B592   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationByName:
    mov dword ptr [currentHash], 0x0E70F1F6C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationEnlistment:
    mov dword ptr [currentHash], 0x0264639EC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationJobObject:
    mov dword ptr [currentHash], 0x0C4592CC5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationPort:
    mov dword ptr [currentHash], 0x0920FB59C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationResourceManager:
    mov dword ptr [currentHash], 0x00FB2919E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransaction:
    mov dword ptr [currentHash], 0x00C982C0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransactionManager:
    mov dword ptr [currentHash], 0x0C7A72CDF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationWorkerFactory:
    mov dword ptr [currentHash], 0x002921C16   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInstallUILanguage:
    mov dword ptr [currentHash], 0x017B127EA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIntervalProfile:
    mov dword ptr [currentHash], 0x0AC3DA4AE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIoCompletion:
    mov dword ptr [currentHash], 0x0D44FD6DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryLicenseValue:
    mov dword ptr [currentHash], 0x02C911B3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMultipleValueKey:
    mov dword ptr [currentHash], 0x0AD19D0EA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMutant:
    mov dword ptr [currentHash], 0x096B0913B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeys:
    mov dword ptr [currentHash], 0x04BB626A8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeysEx:
    mov dword ptr [currentHash], 0x0E319B7C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPortInformationProcess:
    mov dword ptr [currentHash], 0x05F927806   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryQuotaInformationFile:
    mov dword ptr [currentHash], 0x077C5FEE7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityAttributesToken:
    mov dword ptr [currentHash], 0x07BDE4D76   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityObject:
    mov dword ptr [currentHash], 0x090BFA0F3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityPolicy:
    mov dword ptr [currentHash], 0x0924491DF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySemaphore:
    mov dword ptr [currentHash], 0x0FD6197B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySymbolicLinkObject:
    mov dword ptr [currentHash], 0x095B8ABF2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValue:
    mov dword ptr [currentHash], 0x0EEBB8F76   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValueEx:
    mov dword ptr [currentHash], 0x0F7CCB537   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformationEx:
    mov dword ptr [currentHash], 0x0AC916FCB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimerResolution:
    mov dword ptr [currentHash], 0x00E952C59   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateData:
    mov dword ptr [currentHash], 0x0BE05928A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateNameInformation:
    mov dword ptr [currentHash], 0x084D362C7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThreadEx:
    mov dword ptr [currentHash], 0x0A0A0EE66   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseException:
    mov dword ptr [currentHash], 0x006D2298F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseHardError:
    mov dword ptr [currentHash], 0x003911D39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadOnlyEnlistment:
    mov dword ptr [currentHash], 0x049C28E91   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverEnlistment:
    mov dword ptr [currentHash], 0x09B359EA3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverResourceManager:
    mov dword ptr [currentHash], 0x06E35F61F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverTransactionManager:
    mov dword ptr [currentHash], 0x0042EDC04   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterProtocolAddressInformation:
    mov dword ptr [currentHash], 0x0163F1CAB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterThreadTerminatePort:
    mov dword ptr [currentHash], 0x0A23783AA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseKeyedEvent:
    mov dword ptr [currentHash], 0x070C34B44   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseWorkerFactoryWorker:
    mov dword ptr [currentHash], 0x0A4902D8A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletionEx:
    mov dword ptr [currentHash], 0x09CAECE74   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveProcessDebug:
    mov dword ptr [currentHash], 0x022BCCF36   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameKey:
    mov dword ptr [currentHash], 0x0299D0C3E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameTransactionManager:
    mov dword ptr [currentHash], 0x08E319293   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplaceKey:
    mov dword ptr [currentHash], 0x0491C78A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplacePartitionUnit:
    mov dword ptr [currentHash], 0x060B16C32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReplyPort:
    mov dword ptr [currentHash], 0x020B10F6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestPort:
    mov dword ptr [currentHash], 0x05AB65B38   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetEvent:
    mov dword ptr [currentHash], 0x0EB51ECC2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetWriteWatch:
    mov dword ptr [currentHash], 0x098D39446   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRestoreKey:
    mov dword ptr [currentHash], 0x01BC3F6A9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeProcess:
    mov dword ptr [currentHash], 0x0419F7230   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRevertContainerImpersonation:
    mov dword ptr [currentHash], 0x034A21431   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackComplete:
    mov dword ptr [currentHash], 0x068B8741A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackEnlistment:
    mov dword ptr [currentHash], 0x09136B2A1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackRegistryTransaction:
    mov dword ptr [currentHash], 0x070BB5E67   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackTransaction:
    mov dword ptr [currentHash], 0x01CF8004B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollforwardTransactionManager:
    mov dword ptr [currentHash], 0x011C3410E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKey:
    mov dword ptr [currentHash], 0x080016B6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKeyEx:
    mov dword ptr [currentHash], 0x0EB6BDED6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveMergedKeys:
    mov dword ptr [currentHash], 0x0D3B4D6C4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSecureConnectPort:
    mov dword ptr [currentHash], 0x072ED4142   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSerializeBoot:
    mov dword ptr [currentHash], 0x0B0207C61   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootEntryOrder:
    mov dword ptr [currentHash], 0x0CDEFFD41   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootOptions:
    mov dword ptr [currentHash], 0x09F099D9D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel:
    mov dword ptr [currentHash], 0x0CF7DE7A1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel2:
    mov dword ptr [currentHash], 0x06EB2EC62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetContextThread:
    mov dword ptr [currentHash], 0x04CFC0A5D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDebugFilterState:
    mov dword ptr [currentHash], 0x0348E382C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultHardErrorPort:
    mov dword ptr [currentHash], 0x0B8AAB528   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultLocale:
    mov dword ptr [currentHash], 0x085A95D9D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultUILanguage:
    mov dword ptr [currentHash], 0x0AD325030   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDriverEntryOrder:
    mov dword ptr [currentHash], 0x00F9C1D01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEaFile:
    mov dword ptr [currentHash], 0x0533D3DE8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighEventPair:
    mov dword ptr [currentHash], 0x0A6AF463D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighWaitLowEventPair:
    mov dword ptr [currentHash], 0x0A6B5AA27   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIRTimer:
    mov dword ptr [currentHash], 0x0CD9D38FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationDebugObject:
    mov dword ptr [currentHash], 0x018382487   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationEnlistment:
    mov dword ptr [currentHash], 0x00B6410F3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationJobObject:
    mov dword ptr [currentHash], 0x01A25FA79   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationKey:
    mov dword ptr [currentHash], 0x0F2C103B9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationResourceManager:
    mov dword ptr [currentHash], 0x031965B0A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationSymbolicLink:
    mov dword ptr [currentHash], 0x0FAA72212   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationToken:
    mov dword ptr [currentHash], 0x00386750E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransaction:
    mov dword ptr [currentHash], 0x028823A2F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransactionManager:
    mov dword ptr [currentHash], 0x0AB96218B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationVirtualMemory:
    mov dword ptr [currentHash], 0x01B911D1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationWorkerFactory:
    mov dword ptr [currentHash], 0x08A2290B6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIntervalProfile:
    mov dword ptr [currentHash], 0x02581DD85   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletion:
    mov dword ptr [currentHash], 0x002980237   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletionEx:
    mov dword ptr [currentHash], 0x08CAEC268   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLdtEntries:
    mov dword ptr [currentHash], 0x0FB53ECFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowEventPair:
    mov dword ptr [currentHash], 0x016B1CAE3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowWaitHighEventPair:
    mov dword ptr [currentHash], 0x0F2D21640   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetQuotaInformationFile:
    mov dword ptr [currentHash], 0x09706A793   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSecurityObject:
    mov dword ptr [currentHash], 0x016B85055   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValue:
    mov dword ptr [currentHash], 0x0C457E39C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValueEx:
    mov dword ptr [currentHash], 0x037CBF2B6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemInformation:
    mov dword ptr [currentHash], 0x0036F07FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemPowerState:
    mov dword ptr [currentHash], 0x06C8F86C2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemTime:
    mov dword ptr [currentHash], 0x08725CE82   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetThreadExecutionState:
    mov dword ptr [currentHash], 0x0923D7C34   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer2:
    mov dword ptr [currentHash], 0x079929A43   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerEx:
    mov dword ptr [currentHash], 0x072E8ACBE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerResolution:
    mov dword ptr [currentHash], 0x041146399   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetUuidSeed:
    mov dword ptr [currentHash], 0x0D14ED7D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetVolumeInformationFile:
    mov dword ptr [currentHash], 0x024B1D2A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetWnfProcessNotificationEvent:
    mov dword ptr [currentHash], 0x0999D8030   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownSystem:
    mov dword ptr [currentHash], 0x0D36EC9C1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownWorkerFactory:
    mov dword ptr [currentHash], 0x0151D1594   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSignalAndWaitForSingleObject:
    mov dword ptr [currentHash], 0x00AB43429   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSinglePhaseReject:
    mov dword ptr [currentHash], 0x0745E2285   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartProfile:
    mov dword ptr [currentHash], 0x058942A5C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStopProfile:
    mov dword ptr [currentHash], 0x08F1B7843   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSubscribeWnfStateChange:
    mov dword ptr [currentHash], 0x036A72F3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendProcess:
    mov dword ptr [currentHash], 0x082C1834F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendThread:
    mov dword ptr [currentHash], 0x07CDF2E69   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSystemDebugControl:
    mov dword ptr [currentHash], 0x0D78BF51D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateEnclave:
    mov dword ptr [currentHash], 0x04A8B16B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateJobObject:
    mov dword ptr [currentHash], 0x0188433DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTestAlert:
    mov dword ptr [currentHash], 0x066379875   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawRegistry:
    mov dword ptr [currentHash], 0x032A03229   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawTransactions:
    mov dword ptr [currentHash], 0x0F144D313   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceControl:
    mov dword ptr [currentHash], 0x00552E3C0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTranslateFilePath:
    mov dword ptr [currentHash], 0x0873F6C6B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUmsThreadYield:
    mov dword ptr [currentHash], 0x03FA60EF3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadDriver:
    mov dword ptr [currentHash], 0x016B73BE8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey:
    mov dword ptr [currentHash], 0x01A2F63DD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey2:
    mov dword ptr [currentHash], 0x0C7350282   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKeyEx:
    mov dword ptr [currentHash], 0x099F2AF4F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockFile:
    mov dword ptr [currentHash], 0x03298E3D2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockVirtualMemory:
    mov dword ptr [currentHash], 0x005966B01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSectionEx:
    mov dword ptr [currentHash], 0x09B1D5659   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnsubscribeWnfStateChange:
    mov dword ptr [currentHash], 0x082400D68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUpdateWnfStateData:
    mov dword ptr [currentHash], 0x062B9740E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtVdmControl:
    mov dword ptr [currentHash], 0x05DB24511   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForAlertByThreadId:
    mov dword ptr [currentHash], 0x09AAE3A6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForDebugEvent:
    mov dword ptr [currentHash], 0x03E9BC0E9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForKeyedEvent:
    mov dword ptr [currentHash], 0x0EB0AEA9F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWorkViaWorkerFactory:
    mov dword ptr [currentHash], 0x0C091CA00   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitHighEventPair:
    mov dword ptr [currentHash], 0x0219FDE96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitLowEventPair:
    mov dword ptr [currentHash], 0x0203804A9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireCMFViewOwnership:
    mov dword ptr [currentHash], 0x0DA4C1D1A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelDeviceWakeupRequest:
    mov dword ptr [currentHash], 0x073816522   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearAllSavepointsTransaction:
    mov dword ptr [currentHash], 0x01A0E44C7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearSavepointTransaction:
    mov dword ptr [currentHash], 0x0DCB3D223   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackSavepointTransaction:
    mov dword ptr [currentHash], 0x0144F351C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointTransaction:
    mov dword ptr [currentHash], 0x04CD76C19   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointComplete:
    mov dword ptr [currentHash], 0x0009AF898   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSectionEx:
    mov dword ptr [currentHash], 0x080953FB3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateCrossVmEvent:
    mov dword ptr [currentHash], 0x01B2074B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetPlugPlayEvent:
    mov dword ptr [currentHash], 0x00E088D1E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListTransactions:
    mov dword ptr [currentHash], 0x0B8299EB8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMarshallTransaction:
    mov dword ptr [currentHash], 0x032A62A0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPullTransaction:
    mov dword ptr [currentHash], 0x0040B2499   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseCMFViewOwnership:
    mov dword ptr [currentHash], 0x034AD2036   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWnfNotifications:
    mov dword ptr [currentHash], 0x05B896703   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartTm:
    mov dword ptr [currentHash], 0x0D19DFE2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationProcess:
    mov dword ptr [currentHash], 0x096288E47   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestDeviceWakeup:
    mov dword ptr [currentHash], 0x02EA1223C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWakeupLatency:
    mov dword ptr [currentHash], 0x0904BB1E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemTime:
    mov dword ptr [currentHash], 0x0B6AEC6BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManageHotPatch:
    mov dword ptr [currentHash], 0x068A5287E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinueEx:
    mov dword ptr [currentHash], 0x0D34D0411   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


RtlCreateUserThread:
    mov dword ptr [currentHash], 0x0B4AF2B95   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


