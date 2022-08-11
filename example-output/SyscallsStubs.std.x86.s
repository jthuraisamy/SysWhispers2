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
    push 0xA9019EDB
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x279B1D25
    call _WhisperMain

_NtAcceptConnectPort:
    push 0xA63D2532
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0x1BA32709
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x9AA0BAFC
    call _WhisperMain

_NtCallbackReturn:
    push 0x068C251C
    call _WhisperMain

_NtReadFile:
    push 0x4098542E
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0x64F2B7C6
    call _WhisperMain

_NtWriteFile:
    push 0xF1DBDB5D
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x4EA84E3F
    call _WhisperMain

_NtReleaseSemaphore:
    push 0x76E47870
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x6AF2899C
    call _WhisperMain

_NtReplyPort:
    push 0x20B11F12
    call _WhisperMain

_NtSetInformationThread:
    push 0xF65ABCF3
    call _WhisperMain

_NtSetEvent:
    push 0x0E910704
    call _WhisperMain

_NtClose:
    push 0xDC482529
    call _WhisperMain

_NtQueryObject:
    push 0x043FDD12
    call _WhisperMain

_NtQueryInformationFile:
    push 0x3EDFC498
    call _WhisperMain

_NtOpenKey:
    push 0x249C4949
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x271BC085
    call _WhisperMain

_NtFindAtom:
    push 0xDF41D0DB
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0xD138E3EF
    call _WhisperMain

_NtQueryKey:
    push 0x0B173288
    call _WhisperMain

_NtQueryValueKey:
    push 0x221CD262
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x0F8D111B
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x802C8FB1
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x408E5C41
    call _WhisperMain

_NtWriteFileGather:
    push 0xBB3FEDFB
    call _WhisperMain

_NtCreateKey:
    push 0x8D1F6008
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x03997D1F
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0xE570FAFB
    call _WhisperMain

_NtReleaseMutant:
    push 0x20A46D7C
    call _WhisperMain

_NtQueryInformationToken:
    push 0x8792109A
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0xD37FD6F7
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0x43916F45
    call _WhisperMain

_NtOpenThreadToken:
    push 0x015B9873
    call _WhisperMain

_NtQueryInformationThread:
    push 0x705F2C9E
    call _WhisperMain

_NtOpenProcess:
    push 0xD554CCD8
    call _WhisperMain

_NtSetInformationFile:
    push 0x9C38540E
    call _WhisperMain

_NtMapViewOfSection:
    push 0x0E962FC5
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0x76B1B6EE
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0x12813051
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0x6D6F33BA
    call _WhisperMain

_NtTerminateProcess:
    push 0xEFAF0A3F
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0x18A10E0E
    call _WhisperMain

_NtReadFileScatter:
    push 0x5BD20D17
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x1B285B10
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0xB0A9F414
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x51F84F55
    call _WhisperMain

_NtEnumerateKey:
    push 0x09AF4870
    call _WhisperMain

_NtOpenFile:
    push 0x2A846226
    call _WhisperMain

_NtDelayExecution:
    push 0x4EC24853
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x3F9EFEB8
    call _WhisperMain

_NtQuerySystemInformation:
    push 0x0D930D01
    call _WhisperMain

_NtOpenSection:
    push 0x1853EA17
    call _WhisperMain

_NtQueryTimer:
    push 0xBD978D3A
    call _WhisperMain

_NtFsControlFile:
    push 0x64F5222E
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x0F9918F7
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x1A95928A
    call _WhisperMain

_NtDuplicateObject:
    push 0xE45F2C03
    call _WhisperMain

_NtQueryAttributesFile:
    push 0x615895C9
    call _WhisperMain

_NtClearEvent:
    push 0x6ECF6752
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x09BD1F23
    call _WhisperMain

_NtOpenEvent:
    push 0x08821906
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0x3DA3650A
    call _WhisperMain

_NtDuplicateToken:
    push 0x7B10817C
    call _WhisperMain

_NtContinue:
    push 0xDEB435C7
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0xF5D7FA65
    call _WhisperMain

_NtQueueApcThread:
    push 0x14CF7017
    call _WhisperMain

_NtYieldExecution:
    push 0x0397CDCA
    call _WhisperMain

_NtAddAtom:
    push 0x1DB03E29
    call _WhisperMain

_NtCreateEvent:
    push 0x51034E68
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0xED742BD5
    call _WhisperMain

_NtCreateSection:
    push 0xBC9BE029
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x70FA7E52
    call _WhisperMain

_NtApphelpCacheControl:
    push 0x49A1B3E7
    call _WhisperMain

_NtCreateProcessEx:
    push 0x9210A0AA
    call _WhisperMain

_NtCreateThread:
    push 0x26BC2015
    call _WhisperMain

_NtIsProcessInJob:
    push 0xE5979949
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0xBB18B18B
    call _WhisperMain

_NtQuerySection:
    push 0x9C35BEA5
    call _WhisperMain

_NtResumeThread:
    push 0x32927E31
    call _WhisperMain

_NtTerminateThread:
    push 0x0C179F28
    call _WhisperMain

_NtReadRequestData:
    push 0xB805B2AE
    call _WhisperMain

_NtCreateFile:
    push 0x9E9CAC04
    call _WhisperMain

_NtQueryEvent:
    push 0xF8EB1CFC
    call _WhisperMain

_NtWriteRequestData:
    push 0xCECA5FFB
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x2B38D976
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0x8F30935F
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0x119D2D13
    call _WhisperMain

_NtSetInformationObject:
    push 0x88151919
    call _WhisperMain

_NtCancelIoFile:
    push 0xA4EAB262
    call _WhisperMain

_NtTraceEvent:
    push 0x0EAC1F08
    call _WhisperMain

_NtPowerInformation:
    push 0x66B04663
    call _WhisperMain

_NtSetValueKey:
    push 0x8ACE4995
    call _WhisperMain

_NtCancelTimer:
    push 0xB5A0C75D
    call _WhisperMain

_NtSetTimer:
    push 0x0394393C
    call _WhisperMain

_NtAccessCheckByType:
    push 0x52FFBBAA
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0x56F9586A
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0x3EA31E2E
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0x18340882
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0xEF5AE9E7
    call _WhisperMain

_NtAddAtomEx:
    push 0xA59AF542
    call _WhisperMain

_NtAddBootEntry:
    push 0xA174B5D8
    call _WhisperMain

_NtAddDriverEntry:
    push 0x1984096C
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0xA041F6E5
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x39E51CB5
    call _WhisperMain

_NtAlertResumeThread:
    push 0xCE9B043D
    call _WhisperMain

_NtAlertThread:
    push 0x7C47E779
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0xB32F1E2F
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0x3DCE1F48
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x7A5A04B7
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0x7BE31438
    call _WhisperMain

_NtAllocateUuids:
    push 0x1A8B1A17
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0xA089F253
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0xE0B31EC1
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0xBA95AB2F
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x62CE7F66
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0xA7A86A9C
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x24BEC0D1
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0xB2AC56F7
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x7AC96C79
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0x8A0CB78B
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0xB690DB09
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0xF2E819B0
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0x2ADB045B
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0xF7D1CC5A
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0x0EB20922
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0xA832B99C
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0xE47FFFF0
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0x5CF17968
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0xD5B5DA29
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x8C205696
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0xBAABDCBF
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0x13CCD0F0
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0x0E5405DC
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x6CF789E6
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x008E2FD3
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0xD74AEEEE
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x0C31852C
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x0833388E
    call _WhisperMain

_NtCallEnclave:
    push 0x1A961A3C
    call _WhisperMain

_NtCancelIoFileEx:
    push 0x9089DC52
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0xF6C68015
    call _WhisperMain

_NtCancelTimer2:
    push 0xE81515BA
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0x881D8E8F
    call _WhisperMain

_NtCommitComplete:
    push 0x38AC002E
    call _WhisperMain

_NtCommitEnlistment:
    push 0xC226DBA2
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0xBAB5B825
    call _WhisperMain

_NtCommitTransaction:
    push 0x08802FD5
    call _WhisperMain

_NtCompactKeys:
    push 0x218E320A
    call _WhisperMain

_NtCompareObjects:
    push 0x43D94753
    call _WhisperMain

_NtCompareSigningLevels:
    push 0x40920046
    call _WhisperMain

_NtCompareTokens:
    push 0x55DD3B01
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x2172C21D
    call _WhisperMain

_NtCompressKey:
    push 0x1494070F
    call _WhisperMain

_NtConnectPort:
    push 0x3CB1253C
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x0BAA2533
    call _WhisperMain

_NtCreateDebugObject:
    push 0x02BCEAC0
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x1AA5E4D8
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0x7C7C820A
    call _WhisperMain

_NtCreateEnclave:
    push 0xC691F25A
    call _WhisperMain

_NtCreateEnlistment:
    push 0x3FD91D8F
    call _WhisperMain

_NtCreateEventPair:
    push 0x10B64E7F
    call _WhisperMain

_NtCreateIRTimer:
    push 0x3D851B32
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x030C65D9
    call _WhisperMain

_NtCreateJobObject:
    push 0x8CA1E65E
    call _WhisperMain

_NtCreateJobSet:
    push 0x82031A2F
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0x168A9797
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0xFE40BF96
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0xC3A1CD3E
    call _WhisperMain

_NtCreateMailslotFile:
    push 0xA7B12F95
    call _WhisperMain

_NtCreateMutant:
    push 0xD34E2848
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x68F88CA2
    call _WhisperMain

_NtCreatePagingFile:
    push 0xD17C3A7D
    call _WhisperMain

_NtCreatePartition:
    push 0x8D2CE5F6
    call _WhisperMain

_NtCreatePort:
    push 0xA276A3FA
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x8C2F4972
    call _WhisperMain

_NtCreateProcess:
    push 0x3F9D2DF2
    call _WhisperMain

_NtCreateProfile:
    push 0x04847E04
    call _WhisperMain

_NtCreateProfileEx:
    push 0x7A804447
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x84ABC67A
    call _WhisperMain

_NtCreateResourceManager:
    push 0x78228069
    call _WhisperMain

_NtCreateSemaphore:
    push 0x78A6B50E
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x08199015
    call _WhisperMain

_NtCreateThreadEx:
    push 0x14AB4C6A
    call _WhisperMain

_NtCreateTimer:
    push 0x73D6416A
    call _WhisperMain

_NtCreateTimer2:
    push 0x19A559AB
    call _WhisperMain

_NtCreateToken:
    push 0x67C0594C
    call _WhisperMain

_NtCreateTokenEx:
    push 0x86830DB1
    call _WhisperMain

_NtCreateTransaction:
    push 0xD099D60D
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x05222F9E
    call _WhisperMain

_NtCreateUserProcess:
    push 0x953FAE90
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0xF7C28B29
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x66B24F6E
    call _WhisperMain

_NtCreateWnfStateName:
    push 0xF4B2FD20
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0x04951C72
    call _WhisperMain

_NtDebugActiveProcess:
    push 0xE03DD9B1
    call _WhisperMain

_NtDebugContinue:
    push 0x769689CE
    call _WhisperMain

_NtDeleteAtom:
    push 0xE27EE5EC
    call _WhisperMain

_NtDeleteBootEntry:
    push 0x018D35C0
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0x0F827B0E
    call _WhisperMain

_NtDeleteFile:
    push 0xE245E0DC
    call _WhisperMain

_NtDeleteKey:
    push 0x9F2B8EB0
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x98DEA590
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x3E90470D
    call _WhisperMain

_NtDeleteValueKey:
    push 0x06FB3741
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0xC3793369
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0xED431050
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0xE9C0F37E
    call _WhisperMain

_NtDisplayString:
    push 0x7ECE6A5E
    call _WhisperMain

_NtDrawText:
    push 0xE0BAEB2D
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0xB029493F
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0x2D911828
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0xE153F3CC
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0x43531F97
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0xCEE626CD
    call _WhisperMain

_NtExtendSection:
    push 0x9F90DB3A
    call _WhisperMain

_NtFilterBootOption:
    push 0x048E3803
    call _WhisperMain

_NtFilterToken:
    push 0x07921D1A
    call _WhisperMain

_NtFilterTokenEx:
    push 0x0C875654
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0x0AA9CC97
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0x1FBBD112
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x1526D977
    call _WhisperMain

_NtFlushKey:
    push 0x2D9F0A32
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0xE8B9EE28
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x09A2794B
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0x6DB47D2B
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0x12B3FAA8
    call _WhisperMain

_NtFreezeRegistry:
    push 0x028F15E3
    call _WhisperMain

_NtFreezeTransactions:
    push 0x811EB399
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0x64F8ABA4
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x46CE265B
    call _WhisperMain

_NtGetContextThread:
    push 0x1CF8EEE9
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x0CA2F4E8
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0xDC4B2131
    call _WhisperMain

_NtGetDevicePowerState:
    push 0x3090393C
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0x1DA1010A
    call _WhisperMain

_NtGetNextProcess:
    push 0xC12FC2B0
    call _WhisperMain

_NtGetNextThread:
    push 0x399EF43F
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0x7AD39C47
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0x1F884540
    call _WhisperMain

_NtGetWriteWatch:
    push 0x9059EACA
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x1F810F3C
    call _WhisperMain

_NtImpersonateThread:
    push 0x26872421
    call _WhisperMain

_NtInitializeEnclave:
    push 0xD48B0A2E
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0x9C00BB9A
    call _WhisperMain

_NtInitializeRegistry:
    push 0xDCCD25BC
    call _WhisperMain

_NtInitiatePowerAction:
    push 0x100CF11F
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0x82891F8A
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0x839EC332
    call _WhisperMain

_NtListenPort:
    push 0x6171987F
    call _WhisperMain

_NtLoadDriver:
    push 0xBEA4C9A5
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x42999034
    call _WhisperMain

_NtLoadHotPatch:
    push 0x90CD6BA9
    call _WhisperMain

_NtLoadKey:
    push 0x407CC165
    call _WhisperMain

_NtLoadKey2:
    push 0x253C6F20
    call _WhisperMain

_NtLoadKeyEx:
    push 0x0B19CF44
    call _WhisperMain

_NtLockFile:
    push 0x78F0547A
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0x32D62CB5
    call _WhisperMain

_NtLockRegistryKey:
    push 0x1F27FA45
    call _WhisperMain

_NtLockVirtualMemory:
    push 0xCD5FC9D3
    call _WhisperMain

_NtMakePermanentObject:
    push 0xA4BAAE24
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x849C9E11
    call _WhisperMain

_NtManagePartition:
    push 0x3CB1DE21
    call _WhisperMain

_NtMapCMFModule:
    push 0x4CEE1854
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x49CF5E48
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0xB952E586
    call _WhisperMain

_NtModifyBootEntry:
    push 0x3D9B1738
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x0B961D18
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0xCD7BBBE1
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0x689A244F
    call _WhisperMain

_NtNotifyChangeKey:
    push 0x0AD3E8A8
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0xDFCEA82C
    call _WhisperMain

_NtNotifyChangeSession:
    push 0x67CD4B4E
    call _WhisperMain

_NtOpenEnlistment:
    push 0x09A70C3D
    call _WhisperMain

_NtOpenEventPair:
    push 0x5017B441
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x21544259
    call _WhisperMain

_NtOpenJobObject:
    push 0xC29CEC21
    call _WhisperMain

_NtOpenKeyEx:
    push 0x73D4BF60
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0x130E9110
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0x1C1E50DA
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0x3AB15D6A
    call _WhisperMain

_NtOpenMutant:
    push 0x3CB610E6
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x6EAF6E02
    call _WhisperMain

_NtOpenPartition:
    push 0x78E04669
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0xAE126BB0
    call _WhisperMain

_NtOpenProcessToken:
    push 0x390D01A4
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0xCE85EA5F
    call _WhisperMain

_NtOpenResourceManager:
    push 0x15BDE3BD
    call _WhisperMain

_NtOpenSemaphore:
    push 0x3EB437D8
    call _WhisperMain

_NtOpenSession:
    push 0xF56EF5F8
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0xA63B9E97
    call _WhisperMain

_NtOpenThread:
    push 0xEEC9E46F
    call _WhisperMain

_NtOpenTimer:
    push 0x0FCF7540
    call _WhisperMain

_NtOpenTransaction:
    push 0xCEC5EA57
    call _WhisperMain

_NtOpenTransactionManager:
    push 0xC415D4B7
    call _WhisperMain

_NtPlugPlayControl:
    push 0xB16DD7FF
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x38A1DEAA
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0x0BA4CCFF
    call _WhisperMain

_NtPrepareComplete:
    push 0x1884040A
    call _WhisperMain

_NtPrepareEnlistment:
    push 0x086715F5
    call _WhisperMain

_NtPrivilegeCheck:
    push 0x3497252B
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0x1E5000FC
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0x1F91F00D
    call _WhisperMain

_NtPropagationComplete:
    push 0x2F57C91A
    call _WhisperMain

_NtPropagationFailed:
    push 0x8C9AF84A
    call _WhisperMain

_NtPulseEvent:
    push 0x82BF8928
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0xA81B85BE
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0xDD40F219
    call _WhisperMain

_NtQueryBootOptions:
    push 0x7A15AA30
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x16B43DF8
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0xC5597C59
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0xE73AEDA4
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0xAB9A9331
    call _WhisperMain

_NtQueryEaFile:
    push 0x1E3E991D
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0x9CC89062
    call _WhisperMain

_NtQueryInformationAtom:
    push 0xFE692358
    call _WhisperMain

_NtQueryInformationByName:
    push 0xA61EB9A5
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x861B979E
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0x14BF0E31
    call _WhisperMain

_NtQueryInformationPort:
    push 0x1AB53D1E
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0x0B331392
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0xE14D0A1B
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0x86259A8F
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0xFE6EECE2
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0xEC0EED97
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0xEE59C6CA
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x9E07A285
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x3CA4E8EA
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0x31982403
    call _WhisperMain

_NtQueryMutant:
    push 0x004F01C5
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0x45DD4A42
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x399CF9E4
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x1C025DDE
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0x6D3D3189
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0xE2462E1D
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x2A3454A9
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0xECDAD36D
    call _WhisperMain

_NtQuerySemaphore:
    push 0xF4181594
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x869E8C00
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0x14A2E2B2
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0xF811056B
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0xF69123CF
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x0C9A0C0D
    call _WhisperMain

_NtQueryWnfStateData:
    push 0xA707AC6D
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0x0E907213
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0xC4D91783
    call _WhisperMain

_NtRaiseException:
    push 0x3AEE15B3
    call _WhisperMain

_NtRaiseHardError:
    push 0xC24EE0DE
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0x4C562F41
    call _WhisperMain

_NtRecoverEnlistment:
    push 0xAF92DC15
    call _WhisperMain

_NtRecoverResourceManager:
    push 0xB267D89B
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x098E6716
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x13851510
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0x36F4733A
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0xC04AF9FE
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0x69404395
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x849743E9
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x58A1B6F6
    call _WhisperMain

_NtRenameKey:
    push 0x63FC9FF8
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x2991E0CA
    call _WhisperMain

_NtReplaceKey:
    push 0xA9E78850
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0xA834A2B2
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0xBA38AFB8
    call _WhisperMain

_NtRequestPort:
    push 0x10B22D1C
    call _WhisperMain

_NtResetEvent:
    push 0x68CB6B5C
    call _WhisperMain

_NtResetWriteWatch:
    push 0x0CE1FABE
    call _WhisperMain

_NtRestoreKey:
    push 0xCBF2AE6D
    call _WhisperMain

_NtResumeProcess:
    push 0x65DB6654
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0xC649C6DB
    call _WhisperMain

_NtRollbackComplete:
    push 0x58B47036
    call _WhisperMain

_NtRollbackEnlistment:
    push 0x09A32A34
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0x1853DAFF
    call _WhisperMain

_NtRollbackTransaction:
    push 0xE6CDE257
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x0FB2579C
    call _WhisperMain

_NtSaveKey:
    push 0x43957E22
    call _WhisperMain

_NtSaveKeyEx:
    push 0x3BB0EFEC
    call _WhisperMain

_NtSaveMergedKeys:
    push 0x61DA644C
    call _WhisperMain

_NtSecureConnectPort:
    push 0x64EE4140
    call _WhisperMain

_NtSerializeBoot:
    push 0xACF829E0
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0x714E07B7
    call _WhisperMain

_NtSetBootOptions:
    push 0x539F9DC3
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0x309B7420
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x10ABA14C
    call _WhisperMain

_NtSetContextThread:
    push 0x341FF936
    call _WhisperMain

_NtSetDebugFilterState:
    push 0x0CB2781C
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0x26B23B30
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x353ACB21
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0x15BA1616
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0xF248DAEE
    call _WhisperMain

_NtSetEaFile:
    push 0x36812637
    call _WhisperMain

_NtSetHighEventPair:
    push 0xC29395B2
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0x4C005881
    call _WhisperMain

_NtSetIRTimer:
    push 0x139F1504
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x795A51D9
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0xCD50ECE5
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x24B82225
    call _WhisperMain

_NtSetInformationKey:
    push 0x9085B12D
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0xDE47CAE5
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0x41D54261
    call _WhisperMain

_NtSetInformationToken:
    push 0x2B95753A
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x9813AA9F
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x7B2363A2
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x42535CB7
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x4890306E
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x82157840
    call _WhisperMain

_NtSetIoCompletion:
    push 0x4AA27069
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0x30CAC6B4
    call _WhisperMain

_NtSetLdtEntries:
    push 0x1E87311D
    call _WhisperMain

_NtSetLowEventPair:
    push 0x10B3CCFD
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0x62AE067B
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0x81155931
    call _WhisperMain

_NtSetSecurityObject:
    push 0xA698883A
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0x35265E32
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0xEF14186B
    call _WhisperMain

_NtSetSystemInformation:
    push 0x8C97D237
    call _WhisperMain

_NtSetSystemPowerState:
    push 0xF5B40CE8
    call _WhisperMain

_NtSetSystemTime:
    push 0x9A8EA717
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0x26DDDD82
    call _WhisperMain

_NtSetTimer2:
    push 0x3F979F01
    call _WhisperMain

_NtSetTimerEx:
    push 0x40AF6214
    call _WhisperMain

_NtSetTimerResolution:
    push 0x009A624F
    call _WhisperMain

_NtSetUuidSeed:
    push 0x02401EFF
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0xD647E8D4
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0xF06B1976
    call _WhisperMain

_NtShutdownSystem:
    push 0x04AF2B3C
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0xC096F42B
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0xC69CC001
    call _WhisperMain

_NtSinglePhaseReject:
    push 0x88D6A466
    call _WhisperMain

_NtStartProfile:
    push 0xFC240D70
    call _WhisperMain

_NtStopProfile:
    push 0x049DC2C0
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0xFFBE08E3
    call _WhisperMain

_NtSuspendProcess:
    push 0xFC20DBBD
    call _WhisperMain

_NtSuspendThread:
    push 0x301F3CB6
    call _WhisperMain

_NtSystemDebugControl:
    push 0xC09401C2
    call _WhisperMain

_NtTerminateEnclave:
    push 0xFB9B1A17
    call _WhisperMain

_NtTerminateJobObject:
    push 0xF451E4CD
    call _WhisperMain

_NtTestAlert:
    push 0x4CCE691E
    call _WhisperMain

_NtThawRegistry:
    push 0x1A8E0C1F
    call _WhisperMain

_NtThawTransactions:
    push 0xF6A4904F
    call _WhisperMain

_NtTraceControl:
    push 0x73AC7F4F
    call _WhisperMain

_NtTranslateFilePath:
    push 0x9A144750
    call _WhisperMain

_NtUmsThreadYield:
    push 0xA79B76AF
    call _WhisperMain

_NtUnloadDriver:
    push 0x36A713F4
    call _WhisperMain

_NtUnloadKey:
    push 0xAC00B581
    call _WhisperMain

_NtUnloadKey2:
    push 0x2DACC778
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x93812F45
    call _WhisperMain

_NtUnlockFile:
    push 0xD960EF3B
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0x001260FC
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x52D09268
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0x8425F188
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0xFC4209D8
    call _WhisperMain

_NtVdmControl:
    push 0x0751C1FB
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x60B6106A
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0x0A801B24
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0x80AAE94C
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0x871AAFB5
    call _WhisperMain

_NtWaitHighEventPair:
    push 0x01343783
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x1445ED32
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x74AD6802
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0x9338D3F4
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0x4CB423A9
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0x173117A3
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0xC881F62D
    call _WhisperMain

_NtSavepointTransaction:
    push 0xDA42DCD5
    call _WhisperMain

_NtSavepointComplete:
    push 0x449813B2
    call _WhisperMain

_NtCreateSectionEx:
    push 0x50B393E9
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0xC888CD1E
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0x98B99A2F
    call _WhisperMain

_NtListTransactions:
    push 0x15B77575
    call _WhisperMain

_NtMarshallTransaction:
    push 0x00AA223B
    call _WhisperMain

_NtPullTransaction:
    push 0xC02BE6BB
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x308CDA16
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x0F952B4F
    call _WhisperMain

_NtStartTm:
    push 0xE24E0535
    call _WhisperMain

_NtSetInformationProcess:
    push 0x3994140C
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x05A52EFE
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x962DFBC0
    call _WhisperMain

_NtQuerySystemTime:
    push 0xBA3EB39B
    call _WhisperMain

_NtManageHotPatch:
    push 0x130F9C29
    call _WhisperMain

_NtContinueEx:
    push 0x73722FD6
    call _WhisperMain

_RtlCreateUserThread:
    push 0xA808B6B1
    call _WhisperMain

