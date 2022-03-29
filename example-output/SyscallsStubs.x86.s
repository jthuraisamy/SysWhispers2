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
    push 0xB6D641BB
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x163E3285
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x2EB72D38
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0xD19E1AC6
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x18A02BEF
    call _WhisperMain

_NtCallbackReturn:
    push 0x829013BE
    call _WhisperMain

_NtReadFile:
    push 0x28C05C56
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0xD841A2A6
    call _WhisperMain

_NtWriteFile:
    push 0xC9719FCB
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x16801617
    call _WhisperMain

_NtReleaseSemaphore:
    push 0x1457341A
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x7AB26F32
    call _WhisperMain

_NtReplyPort:
    push 0xDA342B5A
    call _WhisperMain

_NtSetInformationThread:
    push 0x2A8E6857
    call _WhisperMain

_NtSetEvent:
    push 0xCB020C49
    call _WhisperMain

_NtClose:
    push 0x46D16D51
    call _WhisperMain

_NtQueryObject:
    push 0x1F3075CE
    call _WhisperMain

_NtQueryInformationFile:
    push 0x85115D55
    call _WhisperMain

_NtOpenKey:
    push 0x2490F9CA
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x19CD7426
    call _WhisperMain

_NtFindAtom:
    push 0x38AD2144
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0xC221CCB2
    call _WhisperMain

_NtQueryKey:
    push 0x3BE15A1A
    call _WhisperMain

_NtQueryValueKey:
    push 0x1C1D1F87
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x3191457D
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x832D80A2
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0xC85C2D8B
    call _WhisperMain

_NtWriteFileGather:
    push 0x379E6D37
    call _WhisperMain

_NtCreateKey:
    push 0x39002E90
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x01990F0F
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0x58F16D58
    call _WhisperMain

_NtReleaseMutant:
    push 0xBF1C984F
    call _WhisperMain

_NtQueryInformationToken:
    push 0x939DD948
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0x38B1235E
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0x33AE1F39
    call _WhisperMain

_NtOpenThreadToken:
    push 0x1DA027EC
    call _WhisperMain

_NtQueryInformationThread:
    push 0xB207F4A5
    call _WhisperMain

_NtOpenProcess:
    push 0xEAA8F120
    call _WhisperMain

_NtSetInformationFile:
    push 0x725AB909
    call _WhisperMain

_NtMapViewOfSection:
    push 0x22CC205D
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0xDABDE4F0
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0xD28DF657
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0xAF8072D4
    call _WhisperMain

_NtTerminateProcess:
    push 0x77BF5E26
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0x22B3ADB4
    call _WhisperMain

_NtReadFileScatter:
    push 0x058C0D17
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0xBA4FC4B9
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x38AA7A50
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x2B89C793
    call _WhisperMain

_NtEnumerateKey:
    push 0x7ECF5E94
    call _WhisperMain

_NtOpenFile:
    push 0xE77EEFEB
    call _WhisperMain

_NtDelayExecution:
    push 0xC20DE25F
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x3F38BD21
    call _WhisperMain

_NtQuerySystemInformation:
    push 0xEFB51AD7
    call _WhisperMain

_NtOpenSection:
    push 0xDFB2FB39
    call _WhisperMain

_NtQueryTimer:
    push 0x3C16F04C
    call _WhisperMain

_NtFsControlFile:
    push 0xC94297F7
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x0B970317
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x10BFECF0
    call _WhisperMain

_NtDuplicateObject:
    push 0x08B62A2B
    call _WhisperMain

_NtQueryAttributesFile:
    push 0x9DDBBC81
    call _WhisperMain

_NtClearEvent:
    push 0x704ABB1C
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x01910F07
    call _WhisperMain

_NtOpenEvent:
    push 0x004D07C6
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0x9449F4DB
    call _WhisperMain

_NtDuplicateToken:
    push 0x0B9EFF06
    call _WhisperMain

_NtContinue:
    push 0xD55BEACF
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0x9233B5AF
    call _WhisperMain

_NtQueueApcThread:
    push 0x36822C3B
    call _WhisperMain

_NtYieldExecution:
    push 0x60CA061F
    call _WhisperMain

_NtAddAtom:
    push 0x964EF75C
    call _WhisperMain

_NtCreateEvent:
    push 0x00BD7B4A
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0x64C05C66
    call _WhisperMain

_NtCreateSection:
    push 0x3E911CDD
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x7CAB2E9E
    call _WhisperMain

_NtApphelpCacheControl:
    push 0x0FD80B43
    call _WhisperMain

_NtCreateProcessEx:
    push 0x8F8FCD34
    call _WhisperMain

_NtCreateThread:
    push 0x76D96C6F
    call _WhisperMain

_NtIsProcessInJob:
    push 0x29933921
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0x99F38567
    call _WhisperMain

_NtQuerySection:
    push 0xE04BE6DF
    call _WhisperMain

_NtResumeThread:
    push 0x94AD1E8B
    call _WhisperMain

_NtTerminateThread:
    push 0x50800A31
    call _WhisperMain

_NtReadRequestData:
    push 0xC608DEB2
    call _WhisperMain

_NtCreateFile:
    push 0xD87CA29C
    call _WhisperMain

_NtQueryEvent:
    push 0x31746CDC
    call _WhisperMain

_NtWriteRequestData:
    push 0x36BA0E24
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x0BAB657A
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0x5B357D66
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0xF75ADF07
    call _WhisperMain

_NtSetInformationObject:
    push 0x04985645
    call _WhisperMain

_NtCancelIoFile:
    push 0xB8BB5EBF
    call _WhisperMain

_NtTraceEvent:
    push 0x42864312
    call _WhisperMain

_NtPowerInformation:
    push 0xED4BEBD8
    call _WhisperMain

_NtSetValueKey:
    push 0x2AFC0D63
    call _WhisperMain

_NtCancelTimer:
    push 0x8B9FFB1D
    call _WhisperMain

_NtSetTimer:
    push 0x9CA9F453
    call _WhisperMain

_NtAccessCheckByType:
    push 0xB72E5D20
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0x50C2100F
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0x1ABC1024
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0xC04DF8DE
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0x7ACB6B7E
    call _WhisperMain

_NtAddAtomEx:
    push 0xE1132F46
    call _WhisperMain

_NtAddBootEntry:
    push 0x49947D28
    call _WhisperMain

_NtAddDriverEntry:
    push 0x47D2736E
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x1F988590
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x3D973D01
    call _WhisperMain

_NtAlertResumeThread:
    push 0x5CCEDEEF
    call _WhisperMain

_NtAlertThread:
    push 0x20985A45
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0x9CA377E5
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0x378A9940
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x391729BB
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0x5FBE7024
    call _WhisperMain

_NtAllocateUuids:
    push 0x4E575ECB
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0x76EFA8B9
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0xACF19342
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0x8DDE9967
    call _WhisperMain

_NtAlpcConnectPort:
    push 0xA0BE1DB0
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x3D0F71CB
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x22B33D38
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0x06AA263F
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x1A9E1E7F
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0xD048B9D7
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0x56C94B58
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0x36AD10F9
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0xF761E7CA
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x049C293B
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0x9CC79146
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x593058BE
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0xFE760D38
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0xA93184AF
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0xC557C6C8
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x9427D601
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x3CAE4643
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0x93B15C90
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0x772A826B
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0xE1720463
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x00A80239
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0x9734447C
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x1C800A1D
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x098D2332
    call _WhisperMain

_NtCallEnclave:
    push 0x1AAC6E46
    call _WhisperMain

_NtCancelIoFileEx:
    push 0xD8052A7F
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0x38AFEC1C
    call _WhisperMain

_NtCancelTimer2:
    push 0x96143ACA
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0xBB9CC350
    call _WhisperMain

_NtCommitComplete:
    push 0xAA35FCFE
    call _WhisperMain

_NtCommitEnlistment:
    push 0xD76AECDD
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0x0F980302
    call _WhisperMain

_NtCommitTransaction:
    push 0xB329F1F8
    call _WhisperMain

_NtCompactKeys:
    push 0xC3A5FE0B
    call _WhisperMain

_NtCompareObjects:
    push 0x039D0313
    call _WhisperMain

_NtCompareSigningLevels:
    push 0xD043D6D8
    call _WhisperMain

_NtCompareTokens:
    push 0x43C3495B
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x20B52F36
    call _WhisperMain

_NtCompressKey:
    push 0x98CAA368
    call _WhisperMain

_NtConnectPort:
    push 0x66BF195C
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x2B97BF95
    call _WhisperMain

_NtCreateDebugObject:
    push 0x0CA1645D
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x09A1FFDB
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0xF6790F3F
    call _WhisperMain

_NtCreateEnclave:
    push 0x16300A8A
    call _WhisperMain

_NtCreateEnlistment:
    push 0x6BA72A6D
    call _WhisperMain

_NtCreateEventPair:
    push 0x0757F637
    call _WhisperMain

_NtCreateIRTimer:
    push 0x7B996D02
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x52C8725F
    call _WhisperMain

_NtCreateJobObject:
    push 0x96BDAE11
    call _WhisperMain

_NtCreateJobSet:
    push 0x82C28450
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0xECA3351E
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0xE05DDBFA
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0x15349407
    call _WhisperMain

_NtCreateMailslotFile:
    push 0xE97ED3D9
    call _WhisperMain

_NtCreateMutant:
    push 0x7E9E1C88
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x85031D03
    call _WhisperMain

_NtCreatePagingFile:
    push 0x6AFA5BAE
    call _WhisperMain

_NtCreatePartition:
    push 0x36AC163B
    call _WhisperMain

_NtCreatePort:
    push 0xDC4EBFD0
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x96B2AD2D
    call _WhisperMain

_NtCreateProcess:
    push 0x272D24A2
    call _WhisperMain

_NtCreateProfile:
    push 0xF4DDEB67
    call _WhisperMain

_NtCreateProfileEx:
    push 0x05BBD0E7
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x9F87DF55
    call _WhisperMain

_NtCreateResourceManager:
    push 0xBB62C3A8
    call _WhisperMain

_NtCreateSemaphore:
    push 0x109BF8D6
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x0B24F92A
    call _WhisperMain

_NtCreateThreadEx:
    push 0x98B757F1
    call _WhisperMain

_NtCreateTimer:
    push 0x9CB7962C
    call _WhisperMain

_NtCreateTimer2:
    push 0xB02BEFA6
    call _WhisperMain

_NtCreateToken:
    push 0x84AD920E
    call _WhisperMain

_NtCreateTokenEx:
    push 0x20A25258
    call _WhisperMain

_NtCreateTransaction:
    push 0xE237DA9D
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x19A136F0
    call _WhisperMain

_NtCreateUserProcess:
    push 0xEDA3CE3F
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0x073D77C1
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x2871CA1F
    call _WhisperMain

_NtCreateWnfStateName:
    push 0xB4BA5BB1
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0xDCCDF265
    call _WhisperMain

_NtDebugActiveProcess:
    push 0x7E3197AD
    call _WhisperMain

_NtDebugContinue:
    push 0x58D98B96
    call _WhisperMain

_NtDeleteAtom:
    push 0xAD5F2C4D
    call _WhisperMain

_NtDeleteBootEntry:
    push 0x0D951502
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0xCA96DE0B
    call _WhisperMain

_NtDeleteFile:
    push 0x14B3DE16
    call _WhisperMain

_NtDeleteKey:
    push 0x69D34464
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x74DA8FD6
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x1CAD3F35
    call _WhisperMain

_NtDeleteValueKey:
    push 0xC51D1046
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0x134B3F87
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0x8A8D871D
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0x15CB8BF0
    call _WhisperMain

_NtDisplayString:
    push 0x68909F00
    call _WhisperMain

_NtDrawText:
    push 0xD34AD0DD
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0x6BF90732
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0x0E963B09
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x2C96B699
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0xD19DE521
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x0C90361D
    call _WhisperMain

_NtExtendSection:
    push 0x128A3019
    call _WhisperMain

_NtFilterBootOption:
    push 0x0EA60E33
    call _WhisperMain

_NtFilterToken:
    push 0xC355ADCA
    call _WhisperMain

_NtFilterTokenEx:
    push 0x769F2A4A
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0xA634616A
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0x0FD14672
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x4D9BB1DB
    call _WhisperMain

_NtFlushKey:
    push 0x19CEE8B6
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0x79399F6A
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x3FA90907
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0x802BDAE2
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0x7BE16462
    call _WhisperMain

_NtFreezeRegistry:
    push 0x0E6A100F
    call _WhisperMain

_NtFreezeTransactions:
    push 0x0F4A05DD
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0x969A1DA4
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x4C922453
    call _WhisperMain

_NtGetContextThread:
    push 0x54D01671
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x9A3B8A99
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0x86A2C25E
    call _WhisperMain

_NtGetDevicePowerState:
    push 0x36893E26
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0xFC74C8F1
    call _WhisperMain

_NtGetNextProcess:
    push 0x863B9757
    call _WhisperMain

_NtGetNextThread:
    push 0x8A895136
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0x2292AB8D
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0x0F3F1194
    call _WhisperMain

_NtGetWriteWatch:
    push 0xB779F9CF
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x0794898C
    call _WhisperMain

_NtImpersonateThread:
    push 0x81A8C174
    call _WhisperMain

_NtInitializeEnclave:
    push 0x883AB77E
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0xFEDEC97A
    call _WhisperMain

_NtInitializeRegistry:
    push 0x198AF1DA
    call _WhisperMain

_NtInitiatePowerAction:
    push 0x08922A07
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0x22BA5568
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0x7BA27317
    call _WhisperMain

_NtListenPort:
    push 0x20B3CF28
    call _WhisperMain

_NtLoadDriver:
    push 0x945DFE86
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x6342B777
    call _WhisperMain

_NtLoadHotPatch:
    push 0x90AEA036
    call _WhisperMain

_NtLoadKey:
    push 0x69209848
    call _WhisperMain

_NtLoadKey2:
    push 0x2149CB54
    call _WhisperMain

_NtLoadKeyEx:
    push 0x63681596
    call _WhisperMain

_NtLockFile:
    push 0x2D74AB69
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0x22C03565
    call _WhisperMain

_NtLockRegistryKey:
    push 0x7621558E
    call _WhisperMain

_NtLockVirtualMemory:
    push 0x19916919
    call _WhisperMain

_NtMakePermanentObject:
    push 0x22BC2C21
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x06984055
    call _WhisperMain

_NtManagePartition:
    push 0x19743BA5
    call _WhisperMain

_NtMapCMFModule:
    push 0x3EF510A6
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x2F9E5E62
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0x02917268
    call _WhisperMain

_NtModifyBootEntry:
    push 0xB9F575A0
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x19820116
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0xEED4AFF2
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0xC92793F2
    call _WhisperMain

_NtNotifyChangeKey:
    push 0x28142F8B
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x23B92826
    call _WhisperMain

_NtNotifyChangeSession:
    push 0x018EEF92
    call _WhisperMain

_NtOpenEnlistment:
    push 0x89D34C85
    call _WhisperMain

_NtOpenEventPair:
    push 0x10B3DCED
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x36A9163B
    call _WhisperMain

_NtOpenJobObject:
    push 0x08B4D919
    call _WhisperMain

_NtOpenKeyEx:
    push 0x4D5A9906
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0xB55EF5E3
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0x26BD7460
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0x46CC615E
    call _WhisperMain

_NtOpenMutant:
    push 0xE8B7F13A
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0xDB5ADFCD
    call _WhisperMain

_NtOpenPartition:
    push 0xCE912CC5
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0xAA8EB728
    call _WhisperMain

_NtOpenProcessToken:
    push 0xB3ED8D40
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x1572C81D
    call _WhisperMain

_NtOpenResourceManager:
    push 0xC71FEFA6
    call _WhisperMain

_NtOpenSemaphore:
    push 0x709E5A5E
    call _WhisperMain

_NtOpenSession:
    push 0xDA909A42
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x0C91040D
    call _WhisperMain

_NtOpenThread:
    push 0xEECCF26F
    call _WhisperMain

_NtOpenTimer:
    push 0x8D249BC0
    call _WhisperMain

_NtOpenTransaction:
    push 0xCEC5EA57
    call _WhisperMain

_NtOpenTransactionManager:
    push 0xC415D4B7
    call _WhisperMain

_NtPlugPlayControl:
    push 0x8E108A88
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x054071AC
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0xCB55CEC3
    call _WhisperMain

_NtPrepareComplete:
    push 0x38B6D025
    call _WhisperMain

_NtPrepareEnlistment:
    push 0x30274DD5
    call _WhisperMain

_NtPrivilegeCheck:
    push 0xC25DF1C1
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0x9334726B
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0x1AA5F2FA
    call _WhisperMain

_NtPropagationComplete:
    push 0x15343DF4
    call _WhisperMain

_NtPropagationFailed:
    push 0x19B69D96
    call _WhisperMain

_NtPulseEvent:
    push 0x30AC153C
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0x78CC82CD
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0x6C3178D0
    call _WhisperMain

_NtQueryBootOptions:
    push 0x4C1B6285
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x76CF1C40
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0x0A1946AD
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0xEC48C0F3
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0x0B2E75C3
    call _WhisperMain

_NtQueryEaFile:
    push 0x38987C42
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0xB0BA5EB2
    call _WhisperMain

_NtQueryInformationAtom:
    push 0x51C3B257
    call _WhisperMain

_NtQueryInformationByName:
    push 0xFADDD389
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x0395320F
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0x04B82DE5
    call _WhisperMain

_NtQueryInformationPort:
    push 0x9932B2AD
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0xEBD3B9F3
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x1ED41C79
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0x35B76176
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0x254E0FEC
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0xCF5CF80C
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0xA061F6DC
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x1BB51EDE
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x3A3F29B4
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0xED24D096
    call _WhisperMain

_NtQueryMutant:
    push 0x7E965F42
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0x8294ED4E
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x77DBA48F
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x19B4241C
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0xBCBBB61F
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0xFC66E4CD
    call _WhisperMain

_NtQuerySecurityObject:
    push 0xEFBD8563
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0x045FF92B
    call _WhisperMain

_NtQuerySemaphore:
    push 0xCD5F32C5
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x132B3377
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0x4CBB7764
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0x23DEEF9A
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0x697D29B5
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x1E816402
    call _WhisperMain

_NtQueryWnfStateData:
    push 0xAC0E8282
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0x9A4BFC9F
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0x98B9269E
    call _WhisperMain

_NtRaiseException:
    push 0x01A8217A
    call _WhisperMain

_NtRaiseHardError:
    push 0x09978393
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0xEEA1CF33
    call _WhisperMain

_NtRecoverEnlistment:
    push 0x11933405
    call _WhisperMain

_NtRecoverResourceManager:
    push 0x4D905F0C
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x82B5B60F
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0xD54EF51C
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0x66F67F62
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0x08890F12
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0xBC8D8A29
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0xB49732A8
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x1050FE46
    call _WhisperMain

_NtRenameKey:
    push 0x1B0C46D8
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x2FA9E7F0
    call _WhisperMain

_NtReplaceKey:
    push 0x66CE7554
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0x22BE3E1E
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0x24B42B2E
    call _WhisperMain

_NtRequestPort:
    push 0xA0374F24
    call _WhisperMain

_NtResetEvent:
    push 0x44CE8F88
    call _WhisperMain

_NtResetWriteWatch:
    push 0xFCE9375A
    call _WhisperMain

_NtRestoreKey:
    push 0xFB3EE7A5
    call _WhisperMain

_NtResumeProcess:
    push 0x11A90C20
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0xC629C4C5
    call _WhisperMain

_NtRollbackComplete:
    push 0x59204DCC
    call _WhisperMain

_NtRollbackEnlistment:
    push 0x31872C15
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0xCA51CAC3
    call _WhisperMain

_NtRollbackTransaction:
    push 0x9CBDDA69
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x03AF9F82
    call _WhisperMain

_NtSaveKey:
    push 0x3BAF2A30
    call _WhisperMain

_NtSaveKeyEx:
    push 0x9798D324
    call _WhisperMain

_NtSaveMergedKeys:
    push 0x67827A6C
    call _WhisperMain

_NtSecureConnectPort:
    push 0x983281BC
    call _WhisperMain

_NtSerializeBoot:
    push 0xCBD8D946
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0x960E8E84
    call _WhisperMain

_NtSetBootOptions:
    push 0x779C2F4B
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0xAABA3194
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x3E10D901
    call _WhisperMain

_NtSetContextThread:
    push 0xAB9BA70B
    call _WhisperMain

_NtSetDebugFilterState:
    push 0xB3316903
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0xA734A0BF
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x452D7FEB
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0x299B6E3A
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0x13A51131
    call _WhisperMain

_NtSetEaFile:
    push 0xC0FA48C8
    call _WhisperMain

_NtSetHighEventPair:
    push 0xD753F5CC
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0x3F6ECE0D
    call _WhisperMain

_NtSetIRTimer:
    push 0x0850DB12
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x8837B8BB
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0x479B3A4D
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x8ED07ACF
    call _WhisperMain

_NtSetInformationKey:
    push 0xC2785060
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0xC41FD0BD
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0xA8A67607
    call _WhisperMain

_NtSetInformationToken:
    push 0x63D6755E
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x1681381D
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x05349715
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x9B028F9F
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x786D108F
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x76A1B0F8
    call _WhisperMain

_NtSetIoCompletion:
    push 0x02D843F7
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0xC92F0C73
    call _WhisperMain

_NtSetLdtEntries:
    push 0x5B6A2499
    call _WhisperMain

_NtSetLowEventPair:
    push 0x40D27C5B
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0xA43DA4A3
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0xA23B5420
    call _WhisperMain

_NtSetSecurityObject:
    push 0xFAD676B9
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0x1C9F0B0C
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0x0F935D4E
    call _WhisperMain

_NtSetSystemInformation:
    push 0x072F4385
    call _WhisperMain

_NtSetSystemPowerState:
    push 0x10892602
    call _WhisperMain

_NtSetSystemTime:
    push 0x3EAD353D
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0x12B3ECA8
    call _WhisperMain

_NtSetTimer2:
    push 0xCF356FAB
    call _WhisperMain

_NtSetTimerEx:
    push 0x1CFA2E40
    call _WhisperMain

_NtSetTimerResolution:
    push 0x54CE745D
    call _WhisperMain

_NtSetUuidSeed:
    push 0x1DCF5F12
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0x3402BB21
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x16CB77DE
    call _WhisperMain

_NtShutdownSystem:
    push 0xC0ECECB7
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0x189320D4
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0x29111FA8
    call _WhisperMain

_NtSinglePhaseReject:
    push 0x249E3611
    call _WhisperMain

_NtStartProfile:
    push 0x60356B93
    call _WhisperMain

_NtStopProfile:
    push 0xE5B21DE6
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x06A77F3A
    call _WhisperMain

_NtSuspendProcess:
    push 0x77AB5232
    call _WhisperMain

_NtSuspendThread:
    push 0x1CBD5E1B
    call _WhisperMain

_NtSystemDebugControl:
    push 0xBDAC5CBA
    call _WhisperMain

_NtTerminateEnclave:
    push 0x613E59E2
    call _WhisperMain

_NtTerminateJobObject:
    push 0x1EA037FD
    call _WhisperMain

_NtTestAlert:
    push 0x8CAFE33C
    call _WhisperMain

_NtThawRegistry:
    push 0x3EAC3439
    call _WhisperMain

_NtThawTransactions:
    push 0x900AF0DE
    call _WhisperMain

_NtTraceControl:
    push 0xB865DEF4
    call _WhisperMain

_NtTranslateFilePath:
    push 0xF2B2CFE7
    call _WhisperMain

_NtUmsThreadYield:
    push 0x09B78290
    call _WhisperMain

_NtUnloadDriver:
    push 0x9CD7A65B
    call _WhisperMain

_NtUnloadKey:
    push 0x5B2C58B5
    call _WhisperMain

_NtUnloadKey2:
    push 0xEE7706E9
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x3F99C3E2
    call _WhisperMain

_NtUnlockFile:
    push 0xE1781BFF
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0x0F98213F
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x40DA1604
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0x209C6524
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0x0C851638
    call _WhisperMain

_NtVdmControl:
    push 0x1BC3E185
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x6CABA912
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0x968A759C
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0xF918FC89
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0x489E7A52
    call _WhisperMain

_NtWaitHighEventPair:
    push 0x23332BA4
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x72DF924D
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x0B4D01D4
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0xD421DCA5
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0x9E05BE8B
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0xFD69C1A2
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0x1C47DE17
    call _WhisperMain

_NtSavepointTransaction:
    push 0x1C844249
    call _WhisperMain

_NtSavepointComplete:
    push 0x1A90361A
    call _WhisperMain

_NtCreateSectionEx:
    push 0x984DC69B
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0xC951D0DF
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0xE0452617
    call _WhisperMain

_NtListTransactions:
    push 0xECB6E62C
    call _WhisperMain

_NtMarshallTransaction:
    push 0x7ADD647D
    call _WhisperMain

_NtPullTransaction:
    push 0x7D557FF9
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x5A6F42F8
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x0D992ACB
    call _WhisperMain

_NtStartTm:
    push 0xC38E50AF
    call _WhisperMain

_NtSetInformationProcess:
    push 0x6DAF4A7C
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x5517B042
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x043EE142
    call _WhisperMain

_NtQuerySystemTime:
    push 0xEAAEF31B
    call _WhisperMain

_NtManageHotPatch:
    push 0xF0D1E66E
    call _WhisperMain

_NtContinueEx:
    push 0x2794F0CB
    call _WhisperMain

_RtlCreateUserThread:
    push 0x16AE441F
    call _WhisperMain

