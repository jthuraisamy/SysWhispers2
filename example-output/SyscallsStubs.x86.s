.intel_syntax noprefix

.text
.global _NtAccessCheck
.global _NtWorkerFactoryWorkerReady
.global _NtAcceptConnectPort
.global _NtMapUserPhysicalPagesScatter
.global _NtWaitForSingleObject
.global _NtCallbackReturn
.global _NtReadFile
.global _NtDeviceIoControlFile
.global _NtWriteFile
.global _NtRemoveIoCompletion
.global _NtReleaseSemaphore
.global _NtReplyWaitReceivePort
.global _NtReplyPort
.global _NtSetInformationThread
.global _NtSetEvent
.global _NtClose
.global _NtQueryObject
.global _NtQueryInformationFile
.global _NtOpenKey
.global _NtEnumerateValueKey
.global _NtFindAtom
.global _NtQueryDefaultLocale
.global _NtQueryKey
.global _NtQueryValueKey
.global _NtAllocateVirtualMemory
.global _NtQueryInformationProcess
.global _NtWaitForMultipleObjects32
.global _NtWriteFileGather
.global _NtCreateKey
.global _NtFreeVirtualMemory
.global _NtImpersonateClientOfPort
.global _NtReleaseMutant
.global _NtQueryInformationToken
.global _NtRequestWaitReplyPort
.global _NtQueryVirtualMemory
.global _NtOpenThreadToken
.global _NtQueryInformationThread
.global _NtOpenProcess
.global _NtSetInformationFile
.global _NtMapViewOfSection
.global _NtAccessCheckAndAuditAlarm
.global _NtUnmapViewOfSection
.global _NtReplyWaitReceivePortEx
.global _NtTerminateProcess
.global _NtSetEventBoostPriority
.global _NtReadFileScatter
.global _NtOpenThreadTokenEx
.global _NtOpenProcessTokenEx
.global _NtQueryPerformanceCounter
.global _NtEnumerateKey
.global _NtOpenFile
.global _NtDelayExecution
.global _NtQueryDirectoryFile
.global _NtQuerySystemInformation
.global _NtOpenSection
.global _NtQueryTimer
.global _NtFsControlFile
.global _NtWriteVirtualMemory
.global _NtCloseObjectAuditAlarm
.global _NtDuplicateObject
.global _NtQueryAttributesFile
.global _NtClearEvent
.global _NtReadVirtualMemory
.global _NtOpenEvent
.global _NtAdjustPrivilegesToken
.global _NtDuplicateToken
.global _NtContinue
.global _NtQueryDefaultUILanguage
.global _NtQueueApcThread
.global _NtYieldExecution
.global _NtAddAtom
.global _NtCreateEvent
.global _NtQueryVolumeInformationFile
.global _NtCreateSection
.global _NtFlushBuffersFile
.global _NtApphelpCacheControl
.global _NtCreateProcessEx
.global _NtCreateThread
.global _NtIsProcessInJob
.global _NtProtectVirtualMemory
.global _NtQuerySection
.global _NtResumeThread
.global _NtTerminateThread
.global _NtReadRequestData
.global _NtCreateFile
.global _NtQueryEvent
.global _NtWriteRequestData
.global _NtOpenDirectoryObject
.global _NtAccessCheckByTypeAndAuditAlarm
.global _NtWaitForMultipleObjects
.global _NtSetInformationObject
.global _NtCancelIoFile
.global _NtTraceEvent
.global _NtPowerInformation
.global _NtSetValueKey
.global _NtCancelTimer
.global _NtSetTimer
.global _NtAccessCheckByType
.global _NtAccessCheckByTypeResultList
.global _NtAccessCheckByTypeResultListAndAuditAlarm
.global _NtAccessCheckByTypeResultListAndAuditAlarmByHandle
.global _NtAcquireProcessActivityReference
.global _NtAddAtomEx
.global _NtAddBootEntry
.global _NtAddDriverEntry
.global _NtAdjustGroupsToken
.global _NtAdjustTokenClaimsAndDeviceGroups
.global _NtAlertResumeThread
.global _NtAlertThread
.global _NtAlertThreadByThreadId
.global _NtAllocateLocallyUniqueId
.global _NtAllocateReserveObject
.global _NtAllocateUserPhysicalPages
.global _NtAllocateUuids
.global _NtAllocateVirtualMemoryEx
.global _NtAlpcAcceptConnectPort
.global _NtAlpcCancelMessage
.global _NtAlpcConnectPort
.global _NtAlpcConnectPortEx
.global _NtAlpcCreatePort
.global _NtAlpcCreatePortSection
.global _NtAlpcCreateResourceReserve
.global _NtAlpcCreateSectionView
.global _NtAlpcCreateSecurityContext
.global _NtAlpcDeletePortSection
.global _NtAlpcDeleteResourceReserve
.global _NtAlpcDeleteSectionView
.global _NtAlpcDeleteSecurityContext
.global _NtAlpcDisconnectPort
.global _NtAlpcImpersonateClientContainerOfPort
.global _NtAlpcImpersonateClientOfPort
.global _NtAlpcOpenSenderProcess
.global _NtAlpcOpenSenderThread
.global _NtAlpcQueryInformation
.global _NtAlpcQueryInformationMessage
.global _NtAlpcRevokeSecurityContext
.global _NtAlpcSendWaitReceivePort
.global _NtAlpcSetInformation
.global _NtAreMappedFilesTheSame
.global _NtAssignProcessToJobObject
.global _NtAssociateWaitCompletionPacket
.global _NtCallEnclave
.global _NtCancelIoFileEx
.global _NtCancelSynchronousIoFile
.global _NtCancelTimer2
.global _NtCancelWaitCompletionPacket
.global _NtCommitComplete
.global _NtCommitEnlistment
.global _NtCommitRegistryTransaction
.global _NtCommitTransaction
.global _NtCompactKeys
.global _NtCompareObjects
.global _NtCompareSigningLevels
.global _NtCompareTokens
.global _NtCompleteConnectPort
.global _NtCompressKey
.global _NtConnectPort
.global _NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
.global _NtCreateDebugObject
.global _NtCreateDirectoryObject
.global _NtCreateDirectoryObjectEx
.global _NtCreateEnclave
.global _NtCreateEnlistment
.global _NtCreateEventPair
.global _NtCreateIRTimer
.global _NtCreateIoCompletion
.global _NtCreateJobObject
.global _NtCreateJobSet
.global _NtCreateKeyTransacted
.global _NtCreateKeyedEvent
.global _NtCreateLowBoxToken
.global _NtCreateMailslotFile
.global _NtCreateMutant
.global _NtCreateNamedPipeFile
.global _NtCreatePagingFile
.global _NtCreatePartition
.global _NtCreatePort
.global _NtCreatePrivateNamespace
.global _NtCreateProcess
.global _NtCreateProfile
.global _NtCreateProfileEx
.global _NtCreateRegistryTransaction
.global _NtCreateResourceManager
.global _NtCreateSemaphore
.global _NtCreateSymbolicLinkObject
.global _NtCreateThreadEx
.global _NtCreateTimer
.global _NtCreateTimer2
.global _NtCreateToken
.global _NtCreateTokenEx
.global _NtCreateTransaction
.global _NtCreateTransactionManager
.global _NtCreateUserProcess
.global _NtCreateWaitCompletionPacket
.global _NtCreateWaitablePort
.global _NtCreateWnfStateName
.global _NtCreateWorkerFactory
.global _NtDebugActiveProcess
.global _NtDebugContinue
.global _NtDeleteAtom
.global _NtDeleteBootEntry
.global _NtDeleteDriverEntry
.global _NtDeleteFile
.global _NtDeleteKey
.global _NtDeleteObjectAuditAlarm
.global _NtDeletePrivateNamespace
.global _NtDeleteValueKey
.global _NtDeleteWnfStateData
.global _NtDeleteWnfStateName
.global _NtDisableLastKnownGood
.global _NtDisplayString
.global _NtDrawText
.global _NtEnableLastKnownGood
.global _NtEnumerateBootEntries
.global _NtEnumerateDriverEntries
.global _NtEnumerateSystemEnvironmentValuesEx
.global _NtEnumerateTransactionObject
.global _NtExtendSection
.global _NtFilterBootOption
.global _NtFilterToken
.global _NtFilterTokenEx
.global _NtFlushBuffersFileEx
.global _NtFlushInstallUILanguage
.global _NtFlushInstructionCache
.global _NtFlushKey
.global _NtFlushProcessWriteBuffers
.global _NtFlushVirtualMemory
.global _NtFlushWriteBuffer
.global _NtFreeUserPhysicalPages
.global _NtFreezeRegistry
.global _NtFreezeTransactions
.global _NtGetCachedSigningLevel
.global _NtGetCompleteWnfStateSubscription
.global _NtGetContextThread
.global _NtGetCurrentProcessorNumber
.global _NtGetCurrentProcessorNumberEx
.global _NtGetDevicePowerState
.global _NtGetMUIRegistryInfo
.global _NtGetNextProcess
.global _NtGetNextThread
.global _NtGetNlsSectionPtr
.global _NtGetNotificationResourceManager
.global _NtGetWriteWatch
.global _NtImpersonateAnonymousToken
.global _NtImpersonateThread
.global _NtInitializeEnclave
.global _NtInitializeNlsFiles
.global _NtInitializeRegistry
.global _NtInitiatePowerAction
.global _NtIsSystemResumeAutomatic
.global _NtIsUILanguageComitted
.global _NtListenPort
.global _NtLoadDriver
.global _NtLoadEnclaveData
.global _NtLoadHotPatch
.global _NtLoadKey
.global _NtLoadKey2
.global _NtLoadKeyEx
.global _NtLockFile
.global _NtLockProductActivationKeys
.global _NtLockRegistryKey
.global _NtLockVirtualMemory
.global _NtMakePermanentObject
.global _NtMakeTemporaryObject
.global _NtManagePartition
.global _NtMapCMFModule
.global _NtMapUserPhysicalPages
.global _NtMapViewOfSectionEx
.global _NtModifyBootEntry
.global _NtModifyDriverEntry
.global _NtNotifyChangeDirectoryFile
.global _NtNotifyChangeDirectoryFileEx
.global _NtNotifyChangeKey
.global _NtNotifyChangeMultipleKeys
.global _NtNotifyChangeSession
.global _NtOpenEnlistment
.global _NtOpenEventPair
.global _NtOpenIoCompletion
.global _NtOpenJobObject
.global _NtOpenKeyEx
.global _NtOpenKeyTransacted
.global _NtOpenKeyTransactedEx
.global _NtOpenKeyedEvent
.global _NtOpenMutant
.global _NtOpenObjectAuditAlarm
.global _NtOpenPartition
.global _NtOpenPrivateNamespace
.global _NtOpenProcessToken
.global _NtOpenRegistryTransaction
.global _NtOpenResourceManager
.global _NtOpenSemaphore
.global _NtOpenSession
.global _NtOpenSymbolicLinkObject
.global _NtOpenThread
.global _NtOpenTimer
.global _NtOpenTransaction
.global _NtOpenTransactionManager
.global _NtPlugPlayControl
.global _NtPrePrepareComplete
.global _NtPrePrepareEnlistment
.global _NtPrepareComplete
.global _NtPrepareEnlistment
.global _NtPrivilegeCheck
.global _NtPrivilegeObjectAuditAlarm
.global _NtPrivilegedServiceAuditAlarm
.global _NtPropagationComplete
.global _NtPropagationFailed
.global _NtPulseEvent
.global _NtQueryAuxiliaryCounterFrequency
.global _NtQueryBootEntryOrder
.global _NtQueryBootOptions
.global _NtQueryDebugFilterState
.global _NtQueryDirectoryFileEx
.global _NtQueryDirectoryObject
.global _NtQueryDriverEntryOrder
.global _NtQueryEaFile
.global _NtQueryFullAttributesFile
.global _NtQueryInformationAtom
.global _NtQueryInformationByName
.global _NtQueryInformationEnlistment
.global _NtQueryInformationJobObject
.global _NtQueryInformationPort
.global _NtQueryInformationResourceManager
.global _NtQueryInformationTransaction
.global _NtQueryInformationTransactionManager
.global _NtQueryInformationWorkerFactory
.global _NtQueryInstallUILanguage
.global _NtQueryIntervalProfile
.global _NtQueryIoCompletion
.global _NtQueryLicenseValue
.global _NtQueryMultipleValueKey
.global _NtQueryMutant
.global _NtQueryOpenSubKeys
.global _NtQueryOpenSubKeysEx
.global _NtQueryPortInformationProcess
.global _NtQueryQuotaInformationFile
.global _NtQuerySecurityAttributesToken
.global _NtQuerySecurityObject
.global _NtQuerySecurityPolicy
.global _NtQuerySemaphore
.global _NtQuerySymbolicLinkObject
.global _NtQuerySystemEnvironmentValue
.global _NtQuerySystemEnvironmentValueEx
.global _NtQuerySystemInformationEx
.global _NtQueryTimerResolution
.global _NtQueryWnfStateData
.global _NtQueryWnfStateNameInformation
.global _NtQueueApcThreadEx
.global _NtRaiseException
.global _NtRaiseHardError
.global _NtReadOnlyEnlistment
.global _NtRecoverEnlistment
.global _NtRecoverResourceManager
.global _NtRecoverTransactionManager
.global _NtRegisterProtocolAddressInformation
.global _NtRegisterThreadTerminatePort
.global _NtReleaseKeyedEvent
.global _NtReleaseWorkerFactoryWorker
.global _NtRemoveIoCompletionEx
.global _NtRemoveProcessDebug
.global _NtRenameKey
.global _NtRenameTransactionManager
.global _NtReplaceKey
.global _NtReplacePartitionUnit
.global _NtReplyWaitReplyPort
.global _NtRequestPort
.global _NtResetEvent
.global _NtResetWriteWatch
.global _NtRestoreKey
.global _NtResumeProcess
.global _NtRevertContainerImpersonation
.global _NtRollbackComplete
.global _NtRollbackEnlistment
.global _NtRollbackRegistryTransaction
.global _NtRollbackTransaction
.global _NtRollforwardTransactionManager
.global _NtSaveKey
.global _NtSaveKeyEx
.global _NtSaveMergedKeys
.global _NtSecureConnectPort
.global _NtSerializeBoot
.global _NtSetBootEntryOrder
.global _NtSetBootOptions
.global _NtSetCachedSigningLevel
.global _NtSetCachedSigningLevel2
.global _NtSetContextThread
.global _NtSetDebugFilterState
.global _NtSetDefaultHardErrorPort
.global _NtSetDefaultLocale
.global _NtSetDefaultUILanguage
.global _NtSetDriverEntryOrder
.global _NtSetEaFile
.global _NtSetHighEventPair
.global _NtSetHighWaitLowEventPair
.global _NtSetIRTimer
.global _NtSetInformationDebugObject
.global _NtSetInformationEnlistment
.global _NtSetInformationJobObject
.global _NtSetInformationKey
.global _NtSetInformationResourceManager
.global _NtSetInformationSymbolicLink
.global _NtSetInformationToken
.global _NtSetInformationTransaction
.global _NtSetInformationTransactionManager
.global _NtSetInformationVirtualMemory
.global _NtSetInformationWorkerFactory
.global _NtSetIntervalProfile
.global _NtSetIoCompletion
.global _NtSetIoCompletionEx
.global _NtSetLdtEntries
.global _NtSetLowEventPair
.global _NtSetLowWaitHighEventPair
.global _NtSetQuotaInformationFile
.global _NtSetSecurityObject
.global _NtSetSystemEnvironmentValue
.global _NtSetSystemEnvironmentValueEx
.global _NtSetSystemInformation
.global _NtSetSystemPowerState
.global _NtSetSystemTime
.global _NtSetThreadExecutionState
.global _NtSetTimer2
.global _NtSetTimerEx
.global _NtSetTimerResolution
.global _NtSetUuidSeed
.global _NtSetVolumeInformationFile
.global _NtSetWnfProcessNotificationEvent
.global _NtShutdownSystem
.global _NtShutdownWorkerFactory
.global _NtSignalAndWaitForSingleObject
.global _NtSinglePhaseReject
.global _NtStartProfile
.global _NtStopProfile
.global _NtSubscribeWnfStateChange
.global _NtSuspendProcess
.global _NtSuspendThread
.global _NtSystemDebugControl
.global _NtTerminateEnclave
.global _NtTerminateJobObject
.global _NtTestAlert
.global _NtThawRegistry
.global _NtThawTransactions
.global _NtTraceControl
.global _NtTranslateFilePath
.global _NtUmsThreadYield
.global _NtUnloadDriver
.global _NtUnloadKey
.global _NtUnloadKey2
.global _NtUnloadKeyEx
.global _NtUnlockFile
.global _NtUnlockVirtualMemory
.global _NtUnmapViewOfSectionEx
.global _NtUnsubscribeWnfStateChange
.global _NtUpdateWnfStateData
.global _NtVdmControl
.global _NtWaitForAlertByThreadId
.global _NtWaitForDebugEvent
.global _NtWaitForKeyedEvent
.global _NtWaitForWorkViaWorkerFactory
.global _NtWaitHighEventPair
.global _NtWaitLowEventPair
.global _NtAcquireCMFViewOwnership
.global _NtCancelDeviceWakeupRequest
.global _NtClearAllSavepointsTransaction
.global _NtClearSavepointTransaction
.global _NtRollbackSavepointTransaction
.global _NtSavepointTransaction
.global _NtSavepointComplete
.global _NtCreateSectionEx
.global _NtCreateCrossVmEvent
.global _NtGetPlugPlayEvent
.global _NtListTransactions
.global _NtMarshallTransaction
.global _NtPullTransaction
.global _NtReleaseCMFViewOwnership
.global _NtWaitForWnfNotifications
.global _NtStartTm
.global _NtSetInformationProcess
.global _NtRequestDeviceWakeup
.global _NtRequestWakeupLatency
.global _NtQuerySystemTime
.global _NtManageHotPatch
.global _NtContinueEx
.global _RtlCreateUserThread

.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
    ret

_NtAccessCheck:
    push 0xFA40F4F9
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x11A63B35
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x64F17B62
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0x238A0D17
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x009E3E33
    call _WhisperMain

_NtCallbackReturn:
    push 0x168C371A
    call _WhisperMain

_NtReadFile:
    push 0xC544CDF1
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0x22342AD2
    call _WhisperMain

_NtWriteFile:
    push 0xE97AEB1F
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x088E0821
    call _WhisperMain

_NtReleaseSemaphore:
    push 0x34A10CFC
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0xACFE8EA0
    call _WhisperMain

_NtReplyPort:
    push 0x62B0692E
    call _WhisperMain

_NtSetInformationThread:
    push 0x0A2E4E86
    call _WhisperMain

_NtSetEvent:
    push 0x58924AF4
    call _WhisperMain

_NtClose:
    push 0x0352369D
    call _WhisperMain

_NtQueryObject:
    push 0x8CA077CC
    call _WhisperMain

_NtQueryInformationFile:
    push 0xA635B086
    call _WhisperMain

_NtOpenKey:
    push 0x0F1A54C7
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x16AB2319
    call _WhisperMain

_NtFindAtom:
    push 0x3565D433
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0x025D728B
    call _WhisperMain

_NtQueryKey:
    push 0x08172BAC
    call _WhisperMain

_NtQueryValueKey:
    push 0xE15C142E
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x1F88E9E7
    call _WhisperMain

_NtQueryInformationProcess:
    push 0xD99B2213
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x8E9DAF4A
    call _WhisperMain

_NtWriteFileGather:
    push 0x2B907B53
    call _WhisperMain

_NtCreateKey:
    push 0x7EC9073B
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x099E0519
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0x60F36F68
    call _WhisperMain

_NtReleaseMutant:
    push 0x2D4A0AD0
    call _WhisperMain

_NtQueryInformationToken:
    push 0x35AA1F32
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0xE273D9DC
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0x9514A39B
    call _WhisperMain

_NtOpenThreadToken:
    push 0xF8512DEA
    call _WhisperMain

_NtQueryInformationThread:
    push 0x24881E11
    call _WhisperMain

_NtOpenProcess:
    push 0x06AC0521
    call _WhisperMain

_NtSetInformationFile:
    push 0xCA7AC2EC
    call _WhisperMain

_NtMapViewOfSection:
    push 0x04960E0B
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0x0F2EC371
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0x568C3591
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0xA25FEA98
    call _WhisperMain

_NtTerminateProcess:
    push 0xFE26D5BB
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0x30863C0C
    call _WhisperMain

_NtReadFileScatter:
    push 0x159C1D07
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x2FBAF2EF
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x791FB957
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x37D24B39
    call _WhisperMain

_NtEnumerateKey:
    push 0xB6AE97F4
    call _WhisperMain

_NtOpenFile:
    push 0xAD1C2B01
    call _WhisperMain

_NtDelayExecution:
    push 0x520D529F
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x58BBAAE2
    call _WhisperMain

_NtQuerySystemInformation:
    push 0x54CD765D
    call _WhisperMain

_NtOpenSection:
    push 0x0A9E284F
    call _WhisperMain

_NtQueryTimer:
    push 0x179F7F46
    call _WhisperMain

_NtFsControlFile:
    push 0x6AF45662
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x05953B23
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x5CDA584C
    call _WhisperMain

_NtDuplicateObject:
    push 0x3EA1F6FD
    call _WhisperMain

_NtQueryAttributesFile:
    push 0xDD5DD9FD
    call _WhisperMain

_NtClearEvent:
    push 0x200B65DA
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x071473E9
    call _WhisperMain

_NtOpenEvent:
    push 0x30D52978
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0x01940B2D
    call _WhisperMain

_NtDuplicateToken:
    push 0x6DD92558
    call _WhisperMain

_NtContinue:
    push 0x009CD3D0
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0x13C5D178
    call _WhisperMain

_NtQueueApcThread:
    push 0x2E8A0C2B
    call _WhisperMain

_NtYieldExecution:
    push 0x14B63E33
    call _WhisperMain

_NtAddAtom:
    push 0x22BF272E
    call _WhisperMain

_NtCreateEvent:
    push 0xB0B4AF3F
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0xE5B3BD76
    call _WhisperMain

_NtCreateSection:
    push 0x4EC54C51
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x6CFB5E2E
    call _WhisperMain

_NtApphelpCacheControl:
    push 0xFD6DDFBB
    call _WhisperMain

_NtCreateProcessEx:
    push 0xB998FB42
    call _WhisperMain

_NtCreateThread:
    push 0xAF8CB334
    call _WhisperMain

_NtIsProcessInJob:
    push 0x5CE54854
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0x0F940311
    call _WhisperMain

_NtQuerySection:
    push 0x02EC25B9
    call _WhisperMain

_NtResumeThread:
    push 0x7D5445CF
    call _WhisperMain

_NtTerminateThread:
    push 0x228E3037
    call _WhisperMain

_NtReadRequestData:
    push 0xA23EB14C
    call _WhisperMain

_NtCreateFile:
    push 0x2A9AE32E
    call _WhisperMain

_NtQueryEvent:
    push 0x2AB1F0E6
    call _WhisperMain

_NtWriteRequestData:
    push 0x9DC08975
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x3C802E0D
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0xDD42B9D5
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0x61AD6331
    call _WhisperMain

_NtSetInformationObject:
    push 0x271915A7
    call _WhisperMain

_NtCancelIoFile:
    push 0x821B7543
    call _WhisperMain

_NtTraceEvent:
    push 0xCAED7BD0
    call _WhisperMain

_NtPowerInformation:
    push 0x54C25A5F
    call _WhisperMain

_NtSetValueKey:
    push 0x1DC11E58
    call _WhisperMain

_NtCancelTimer:
    push 0x01A23302
    call _WhisperMain

_NtSetTimer:
    push 0x05977F7C
    call _WhisperMain

_NtAccessCheckByType:
    push 0xD442E30A
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0x7EA17221
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0x552A6982
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0x99B41796
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0x1A8958A0
    call _WhisperMain

_NtAddAtomEx:
    push 0x9390C74C
    call _WhisperMain

_NtAddBootEntry:
    push 0x05951912
    call _WhisperMain

_NtAddDriverEntry:
    push 0x3B67B174
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x25971314
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x07900309
    call _WhisperMain

_NtAlertResumeThread:
    push 0xA48BA81A
    call _WhisperMain

_NtAlertThread:
    push 0x1CA4540B
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0xB8A26896
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0xFFE51B65
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x18B4E6C9
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0x19BF3A24
    call _WhisperMain

_NtAllocateUuids:
    push 0x338FFDD3
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0xC8503B3A
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0x30B2213C
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0x73D77E7C
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x3EB1DDDE
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x636DBF29
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x194B9F58
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0xC4F5DE41
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x389F4A77
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0x2CA81D13
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0xFA1DE794
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0x0C982C0B
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0x1888F4C3
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x56EC6753
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0x08B3EDDA
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x22B5D93A
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0x2233A722
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0xD836C9DA
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0xC654C5C9
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0xF85F36ED
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x024618CE
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0xA40091AD
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0x40998DC8
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x22B2A5B8
    call _WhisperMain

_NtAlpcSetInformation:
    push 0xC897E64B
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0xD65AEDFD
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0xFF2A6100
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x07B22910
    call _WhisperMain

_NtCallEnclave:
    push 0x8736BB65
    call _WhisperMain

_NtCancelIoFileEx:
    push 0xF758392D
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0x256033EA
    call _WhisperMain

_NtCancelTimer2:
    push 0x03A35E2D
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0xBC9C9AC6
    call _WhisperMain

_NtCommitComplete:
    push 0x0C9007FE
    call _WhisperMain

_NtCommitEnlistment:
    push 0x164B0FC6
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0x04B43E31
    call _WhisperMain

_NtCommitTransaction:
    push 0x18813A51
    call _WhisperMain

_NtCompactKeys:
    push 0x57BA6A14
    call _WhisperMain

_NtCompareObjects:
    push 0x84648AF6
    call _WhisperMain

_NtCompareSigningLevels:
    push 0xAEF09E73
    call _WhisperMain

_NtCompareTokens:
    push 0xF494EC01
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x3A7637F8
    call _WhisperMain

_NtCompressKey:
    push 0x782E5F8E
    call _WhisperMain

_NtConnectPort:
    push 0xA23C9072
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x79468945
    call _WhisperMain

_NtCreateDebugObject:
    push 0x009E21C3
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0xFAD436BB
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0x426E10B4
    call _WhisperMain

_NtCreateEnclave:
    push 0xCA2FDE86
    call _WhisperMain

_NtCreateEnlistment:
    push 0x0F90ECC7
    call _WhisperMain

_NtCreateEventPair:
    push 0x12B1CCFC
    call _WhisperMain

_NtCreateIRTimer:
    push 0x178C3F36
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x0E1750D7
    call _WhisperMain

_NtCreateJobObject:
    push 0xF65B6E57
    call _WhisperMain

_NtCreateJobSet:
    push 0x8740AF1C
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0xA69A66C6
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0x68CF755E
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0x17C73D1C
    call _WhisperMain

_NtCreateMailslotFile:
    push 0xE47DC2FE
    call _WhisperMain

_NtCreateMutant:
    push 0xFDDC08A5
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0xED7AA75B
    call _WhisperMain

_NtCreatePagingFile:
    push 0x54C36C00
    call _WhisperMain

_NtCreatePartition:
    push 0x444E255D
    call _WhisperMain

_NtCreatePort:
    push 0x2EB4CCDA
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x09B1CFEB
    call _WhisperMain

_NtCreateProcess:
    push 0x81288EB0
    call _WhisperMain

_NtCreateProfile:
    push 0x6E3E6AA4
    call _WhisperMain

_NtCreateProfileEx:
    push 0x029AC0C1
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x970FD3DE
    call _WhisperMain

_NtCreateResourceManager:
    push 0x6E52FA4F
    call _WhisperMain

_NtCreateSemaphore:
    push 0xFCB62D1A
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x83189384
    call _WhisperMain

_NtCreateThreadEx:
    push 0x96A7CC64
    call _WhisperMain

_NtCreateTimer:
    push 0xE58D8F55
    call _WhisperMain

_NtCreateTimer2:
    push 0xB0684CA6
    call _WhisperMain

_NtCreateToken:
    push 0x099F9FBF
    call _WhisperMain

_NtCreateTokenEx:
    push 0x6022A67C
    call _WhisperMain

_NtCreateTransaction:
    push 0x3CEE2243
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x1BA730FA
    call _WhisperMain

_NtCreateUserProcess:
    push 0xEC26CFBB
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0x01813F0A
    call _WhisperMain

_NtCreateWaitablePort:
    push 0xA97288DF
    call _WhisperMain

_NtCreateWnfStateName:
    push 0xCED0FB42
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0x089C140A
    call _WhisperMain

_NtDebugActiveProcess:
    push 0x923099AD
    call _WhisperMain

_NtDebugContinue:
    push 0x5D24BC68
    call _WhisperMain

_NtDeleteAtom:
    push 0xBED35C8B
    call _WhisperMain

_NtDeleteBootEntry:
    push 0x336B3BE4
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0x33930B14
    call _WhisperMain

_NtDeleteFile:
    push 0x6EF46592
    call _WhisperMain

_NtDeleteKey:
    push 0x3AEE1D71
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x16B57464
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x2A88393F
    call _WhisperMain

_NtDeleteValueKey:
    push 0x36820931
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0x32CE441A
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0xA8B02387
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0x386B35C2
    call _WhisperMain

_NtDisplayString:
    push 0x76E83238
    call _WhisperMain

_NtDrawText:
    push 0x4918735E
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0x2DBE03F4
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0x2C97BD9B
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x7CDC2D7F
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0x53AF8FFB
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x96B4A608
    call _WhisperMain

_NtExtendSection:
    push 0x0E8A340F
    call _WhisperMain

_NtFilterBootOption:
    push 0x08A20BCF
    call _WhisperMain

_NtFilterToken:
    push 0x7FD56972
    call _WhisperMain

_NtFilterTokenEx:
    push 0x8E59B5DB
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0x26D4E08A
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0xA5BAD1A1
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x0DAE4997
    call _WhisperMain

_NtFlushKey:
    push 0x9ED4BF6E
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0xD83A3DA2
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x8713938F
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0xA538B5A7
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0xE5BEEE26
    call _WhisperMain

_NtFreezeRegistry:
    push 0x069B203B
    call _WhisperMain

_NtFreezeTransactions:
    push 0x4FAA257D
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0x76BCA01E
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x148F1A13
    call _WhisperMain

_NtGetContextThread:
    push 0x0C9C1E2D
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x8E33C8E6
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0x5AD599AE
    call _WhisperMain

_NtGetDevicePowerState:
    push 0xA43BB4B4
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0x7ACEA663
    call _WhisperMain

_NtGetNextProcess:
    push 0x0DA3362C
    call _WhisperMain

_NtGetNextThread:
    push 0x9A3DD48F
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0xFF5DD282
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0xEFB2719E
    call _WhisperMain

_NtGetWriteWatch:
    push 0x8AA31383
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x3F8F0F22
    call _WhisperMain

_NtImpersonateThread:
    push 0xFA202799
    call _WhisperMain

_NtInitializeEnclave:
    push 0x2C9310D2
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0x744F05AC
    call _WhisperMain

_NtInitializeRegistry:
    push 0x34901C3F
    call _WhisperMain

_NtInitiatePowerAction:
    push 0xC690DF3B
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0xA4A02186
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0xD5EB91C3
    call _WhisperMain

_NtListenPort:
    push 0xDCB0DF3F
    call _WhisperMain

_NtLoadDriver:
    push 0x1C9F4E5C
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x074E907A
    call _WhisperMain

_NtLoadHotPatch:
    push 0x9F721D4F
    call _WhisperMain

_NtLoadKey:
    push 0x3F1844E5
    call _WhisperMain

_NtLoadKey2:
    push 0xDA270AA1
    call _WhisperMain

_NtLoadKeyEx:
    push 0xBBFD8746
    call _WhisperMain

_NtLockFile:
    push 0xE17FCDAF
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0x67E66A7C
    call _WhisperMain

_NtLockRegistryKey:
    push 0x130628B6
    call _WhisperMain

_NtLockVirtualMemory:
    push 0x0B981D77
    call _WhisperMain

_NtMakePermanentObject:
    push 0x243B2EA5
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x263B5ED7
    call _WhisperMain

_NtManagePartition:
    push 0x08B1E6ED
    call _WhisperMain

_NtMapCMFModule:
    push 0x3917A320
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x1142E82C
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0xBE9CE842
    call _WhisperMain

_NtModifyBootEntry:
    push 0x09941D38
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x71E16D64
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0x1999E00D
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0x6B97BFCB
    call _WhisperMain

_NtNotifyChangeKey:
    push 0xCB12AAE8
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x7F837404
    call _WhisperMain

_NtNotifyChangeSession:
    push 0xE78FE71D
    call _WhisperMain

_NtOpenEnlistment:
    push 0xBABADD51
    call _WhisperMain

_NtOpenEventPair:
    push 0x90B047E6
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x0C656AAD
    call _WhisperMain

_NtOpenJobObject:
    push 0x429C0E63
    call _WhisperMain

_NtOpenKeyEx:
    push 0x6BDD9BA6
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0x10CD1A62
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0x86AEC878
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0x50CB5D4A
    call _WhisperMain

_NtOpenMutant:
    push 0x1693FCC5
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x74B25FF4
    call _WhisperMain

_NtOpenPartition:
    push 0x0ABA2FF1
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0xB09231BF
    call _WhisperMain

_NtOpenProcessToken:
    push 0x079A848B
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x9A319AAF
    call _WhisperMain

_NtOpenResourceManager:
    push 0xB66CDF77
    call _WhisperMain

_NtOpenSemaphore:
    push 0xF6A700EF
    call _WhisperMain

_NtOpenSession:
    push 0x0D814956
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x1904FB1A
    call _WhisperMain

_NtOpenThread:
    push 0x1A394106
    call _WhisperMain

_NtOpenTimer:
    push 0xEFDDD16C
    call _WhisperMain

_NtOpenTransaction:
    push 0x05512406
    call _WhisperMain

_NtOpenTransactionManager:
    push 0x75CB4D46
    call _WhisperMain

_NtPlugPlayControl:
    push 0x3DAA0509
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x2CB80836
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0xCBA5EC3E
    call _WhisperMain

_NtPrepareComplete:
    push 0x36B3A4BC
    call _WhisperMain

_NtPrepareEnlistment:
    push 0x09A70C2D
    call _WhisperMain

_NtPrivilegeCheck:
    push 0x369A4D17
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0xE121E24F
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0x18BE3C28
    call _WhisperMain

_NtPropagationComplete:
    push 0xEC50B8DE
    call _WhisperMain

_NtPropagationFailed:
    push 0x3B967B3D
    call _WhisperMain

_NtPulseEvent:
    push 0xB83B91A6
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0x2A98F7CC
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0x1F8FFB1D
    call _WhisperMain

_NtQueryBootOptions:
    push 0x3FA93D3D
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x32B3381C
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0x6A583A81
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0x1E2038BD
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0x030611A3
    call _WhisperMain

_NtQueryEaFile:
    push 0x68B37000
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0x5AC5645E
    call _WhisperMain

_NtQueryInformationAtom:
    push 0x9602B592
    call _WhisperMain

_NtQueryInformationByName:
    push 0xE70F1F6C
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x264639EC
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0xC4592CC5
    call _WhisperMain

_NtQueryInformationPort:
    push 0x920FB59C
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0x0FB2919E
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x0C982C0B
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0xC7A72CDF
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0x02921C16
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0x17B127EA
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0xAC3DA4AE
    call _WhisperMain

_NtQueryIoCompletion:
    push 0xD44FD6DB
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x2C911B3A
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0xAD19D0EA
    call _WhisperMain

_NtQueryMutant:
    push 0x96B0913B
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0x4BB626A8
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0xE319B7C5
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x5F927806
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0x77C5FEE7
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0x7BDE4D76
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x90BFA0F3
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0x924491DF
    call _WhisperMain

_NtQuerySemaphore:
    push 0xFD6197B7
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x95B8ABF2
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0xEEBB8F76
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0xF7CCB537
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0xAC916FCB
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x0E952C59
    call _WhisperMain

_NtQueryWnfStateData:
    push 0xBE05928A
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0x84D362C7
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0xA0A0EE66
    call _WhisperMain

_NtRaiseException:
    push 0x06D2298F
    call _WhisperMain

_NtRaiseHardError:
    push 0x03911D39
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0x49C28E91
    call _WhisperMain

_NtRecoverEnlistment:
    push 0x9B359EA3
    call _WhisperMain

_NtRecoverResourceManager:
    push 0x6E35F61F
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x042EDC04
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x163F1CAB
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0xA23783AA
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0x70C34B44
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0xA4902D8A
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x9CAECE74
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x22BCCF36
    call _WhisperMain

_NtRenameKey:
    push 0x299D0C3E
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x8E319293
    call _WhisperMain

_NtReplaceKey:
    push 0x491C78A6
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0x60B16C32
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0x20B10F6A
    call _WhisperMain

_NtRequestPort:
    push 0x5AB65B38
    call _WhisperMain

_NtResetEvent:
    push 0xEB51ECC2
    call _WhisperMain

_NtResetWriteWatch:
    push 0x98D39446
    call _WhisperMain

_NtRestoreKey:
    push 0x1BC3F6A9
    call _WhisperMain

_NtResumeProcess:
    push 0x419F7230
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0x34A21431
    call _WhisperMain

_NtRollbackComplete:
    push 0x68B8741A
    call _WhisperMain

_NtRollbackEnlistment:
    push 0x9136B2A1
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0x70BB5E67
    call _WhisperMain

_NtRollbackTransaction:
    push 0x1CF8004B
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x11C3410E
    call _WhisperMain

_NtSaveKey:
    push 0x80016B6A
    call _WhisperMain

_NtSaveKeyEx:
    push 0xEB6BDED6
    call _WhisperMain

_NtSaveMergedKeys:
    push 0xD3B4D6C4
    call _WhisperMain

_NtSecureConnectPort:
    push 0x72ED4142
    call _WhisperMain

_NtSerializeBoot:
    push 0xB0207C61
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0xCDEFFD41
    call _WhisperMain

_NtSetBootOptions:
    push 0x9F099D9D
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0xCF7DE7A1
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x6EB2EC62
    call _WhisperMain

_NtSetContextThread:
    push 0x4CFC0A5D
    call _WhisperMain

_NtSetDebugFilterState:
    push 0x348E382C
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0xB8AAB528
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x85A95D9D
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0xAD325030
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0x0F9C1D01
    call _WhisperMain

_NtSetEaFile:
    push 0x533D3DE8
    call _WhisperMain

_NtSetHighEventPair:
    push 0xA6AF463D
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0xA6B5AA27
    call _WhisperMain

_NtSetIRTimer:
    push 0xCD9D38FD
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x18382487
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0x0B6410F3
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x1A25FA79
    call _WhisperMain

_NtSetInformationKey:
    push 0xF2C103B9
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0x31965B0A
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0xFAA72212
    call _WhisperMain

_NtSetInformationToken:
    push 0x0386750E
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x28823A2F
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0xAB96218B
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x1B911D1F
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x8A2290B6
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x2581DD85
    call _WhisperMain

_NtSetIoCompletion:
    push 0x02980237
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0x8CAEC268
    call _WhisperMain

_NtSetLdtEntries:
    push 0xFB53ECFB
    call _WhisperMain

_NtSetLowEventPair:
    push 0x16B1CAE3
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0xF2D21640
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0x9706A793
    call _WhisperMain

_NtSetSecurityObject:
    push 0x16B85055
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0xC457E39C
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0x37CBF2B6
    call _WhisperMain

_NtSetSystemInformation:
    push 0x036F07FD
    call _WhisperMain

_NtSetSystemPowerState:
    push 0x6C8F86C2
    call _WhisperMain

_NtSetSystemTime:
    push 0x8725CE82
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0x923D7C34
    call _WhisperMain

_NtSetTimer2:
    push 0x79929A43
    call _WhisperMain

_NtSetTimerEx:
    push 0x72E8ACBE
    call _WhisperMain

_NtSetTimerResolution:
    push 0x41146399
    call _WhisperMain

_NtSetUuidSeed:
    push 0xD14ED7D4
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0x24B1D2A2
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x999D8030
    call _WhisperMain

_NtShutdownSystem:
    push 0xD36EC9C1
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0x151D1594
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0x0AB43429
    call _WhisperMain

_NtSinglePhaseReject:
    push 0x745E2285
    call _WhisperMain

_NtStartProfile:
    push 0x58942A5C
    call _WhisperMain

_NtStopProfile:
    push 0x8F1B7843
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x36A72F3A
    call _WhisperMain

_NtSuspendProcess:
    push 0x82C1834F
    call _WhisperMain

_NtSuspendThread:
    push 0x7CDF2E69
    call _WhisperMain

_NtSystemDebugControl:
    push 0xD78BF51D
    call _WhisperMain

_NtTerminateEnclave:
    push 0x4A8B16B2
    call _WhisperMain

_NtTerminateJobObject:
    push 0x188433DB
    call _WhisperMain

_NtTestAlert:
    push 0x66379875
    call _WhisperMain

_NtThawRegistry:
    push 0x32A03229
    call _WhisperMain

_NtThawTransactions:
    push 0xF144D313
    call _WhisperMain

_NtTraceControl:
    push 0x0552E3C0
    call _WhisperMain

_NtTranslateFilePath:
    push 0x873F6C6B
    call _WhisperMain

_NtUmsThreadYield:
    push 0x3FA60EF3
    call _WhisperMain

_NtUnloadDriver:
    push 0x16B73BE8
    call _WhisperMain

_NtUnloadKey:
    push 0x1A2F63DD
    call _WhisperMain

_NtUnloadKey2:
    push 0xC7350282
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x99F2AF4F
    call _WhisperMain

_NtUnlockFile:
    push 0x3298E3D2
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0x05966B01
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x9B1D5659
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0x82400D68
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0x62B9740E
    call _WhisperMain

_NtVdmControl:
    push 0x5DB24511
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x9AAE3A6A
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0x3E9BC0E9
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0xEB0AEA9F
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0xC091CA00
    call _WhisperMain

_NtWaitHighEventPair:
    push 0x219FDE96
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x203804A9
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0xDA4C1D1A
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0x73816522
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0x1A0E44C7
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0xDCB3D223
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0x144F351C
    call _WhisperMain

_NtSavepointTransaction:
    push 0x4CD76C19
    call _WhisperMain

_NtSavepointComplete:
    push 0x009AF898
    call _WhisperMain

_NtCreateSectionEx:
    push 0x80953FB3
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0x1B2074B2
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0x0E088D1E
    call _WhisperMain

_NtListTransactions:
    push 0xB8299EB8
    call _WhisperMain

_NtMarshallTransaction:
    push 0x32A62A0D
    call _WhisperMain

_NtPullTransaction:
    push 0x040B2499
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x34AD2036
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x5B896703
    call _WhisperMain

_NtStartTm:
    push 0xD19DFE2D
    call _WhisperMain

_NtSetInformationProcess:
    push 0x96288E47
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x2EA1223C
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x904BB1E6
    call _WhisperMain

_NtQuerySystemTime:
    push 0xB6AEC6BB
    call _WhisperMain

_NtManageHotPatch:
    push 0x68A5287E
    call _WhisperMain

_NtContinueEx:
    push 0xD34D0411
    call _WhisperMain

_RtlCreateUserThread:
    push 0xB4AF2B95
    call _WhisperMain

