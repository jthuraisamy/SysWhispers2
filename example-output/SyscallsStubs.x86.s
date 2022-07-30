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
    push 0x06A6516B
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x87BBED55
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x60EF5F4C
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0xFFEE60E6
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x9A47BA1B
    call _WhisperMain

_NtCallbackReturn:
    push 0x0A992D4C
    call _WhisperMain

_NtReadFile:
    push 0x65238A66
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0x22A4B696
    call _WhisperMain

_NtWriteFile:
    push 0xCC9A9AA9
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x8854EAC5
    call _WhisperMain

_NtReleaseSemaphore:
    push 0x00920877
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x2EB30928
    call _WhisperMain

_NtReplyPort:
    push 0x6EF04328
    call _WhisperMain

_NtSetInformationThread:
    push 0x2505ED21
    call _WhisperMain

_NtSetEvent:
    push 0x0A900D0A
    call _WhisperMain

_NtClose:
    push 0x08904F4B
    call _WhisperMain

_NtQueryObject:
    push 0xCA991A35
    call _WhisperMain

_NtQueryInformationFile:
    push 0xBB104907
    call _WhisperMain

_NtOpenKey:
    push 0x01146E81
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x219E447C
    call _WhisperMain

_NtFindAtom:
    push 0xCD41322B
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0x33AB4571
    call _WhisperMain

_NtQueryKey:
    push 0x859CB626
    call _WhisperMain

_NtQueryValueKey:
    push 0xC21CF5A7
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x7DDF6933
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x8210927D
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x848A0545
    call _WhisperMain

_NtWriteFileGather:
    push 0x73D33167
    call _WhisperMain

_NtCreateKey:
    push 0x3DFC5C06
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x8510978B
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0x3CEC0962
    call _WhisperMain

_NtReleaseMutant:
    push 0x3CBE796E
    call _WhisperMain

_NtQueryInformationToken:
    push 0xAF9E77B4
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0x2CB73522
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0xCF52C3D7
    call _WhisperMain

_NtOpenThreadToken:
    push 0x3FEA3572
    call _WhisperMain

_NtQueryInformationThread:
    push 0x7A402283
    call _WhisperMain

_NtOpenProcess:
    push 0xEDBFCA2F
    call _WhisperMain

_NtSetInformationFile:
    push 0x2968D802
    call _WhisperMain

_NtMapViewOfSection:
    push 0xFCDC0BB8
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0xD9BFE5FE
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0x88918E05
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0xB99AE54E
    call _WhisperMain

_NtTerminateProcess:
    push 0x5B9F378E
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0xD747C3CA
    call _WhisperMain

_NtReadFileScatter:
    push 0x29881721
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x7CE73624
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x5AAA87EF
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x338E10D3
    call _WhisperMain

_NtEnumerateKey:
    push 0x69FE4628
    call _WhisperMain

_NtOpenFile:
    push 0xF919DDC5
    call _WhisperMain

_NtDelayExecution:
    push 0x36AC767F
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x459DB5C9
    call _WhisperMain

_NtQuerySystemInformation:
    push 0x3B6317B9
    call _WhisperMain

_NtOpenSection:
    push 0x970A9398
    call _WhisperMain

_NtQueryTimer:
    push 0x75DE5F42
    call _WhisperMain

_NtFsControlFile:
    push 0x68F9527E
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x06951810
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x2A972E00
    call _WhisperMain

_NtDuplicateObject:
    push 0x1EDC7801
    call _WhisperMain

_NtQueryAttributesFile:
    push 0xA87B324E
    call _WhisperMain

_NtClearEvent:
    push 0x72AF92FA
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x47D37B57
    call _WhisperMain

_NtOpenEvent:
    push 0x08810914
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0x0547F3C3
    call _WhisperMain

_NtDuplicateToken:
    push 0x251115B0
    call _WhisperMain

_NtContinue:
    push 0xA029D3E6
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0x93B1138D
    call _WhisperMain

_NtQueueApcThread:
    push 0x36AC3035
    call _WhisperMain

_NtYieldExecution:
    push 0x0C540AC5
    call _WhisperMain

_NtAddAtom:
    push 0x28BC2D2A
    call _WhisperMain

_NtCreateEvent:
    push 0x28A7051E
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0x4EDF38CC
    call _WhisperMain

_NtCreateSection:
    push 0x08A00A0D
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x5CFABF7C
    call _WhisperMain

_NtApphelpCacheControl:
    push 0xFFB0192A
    call _WhisperMain

_NtCreateProcessEx:
    push 0xE18CD336
    call _WhisperMain

_NtCreateThread:
    push 0x0A90D729
    call _WhisperMain

_NtIsProcessInJob:
    push 0x6F9698C3
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0xCB903DDF
    call _WhisperMain

_NtQuerySection:
    push 0x4A96004F
    call _WhisperMain

_NtResumeThread:
    push 0x20B86211
    call _WhisperMain

_NtTerminateThread:
    push 0xECCEE86E
    call _WhisperMain

_NtReadRequestData:
    push 0x5D2B67B6
    call _WhisperMain

_NtCreateFile:
    push 0x78B82A0C
    call _WhisperMain

_NtQueryEvent:
    push 0xC88ACF00
    call _WhisperMain

_NtWriteRequestData:
    push 0x0E80D2BE
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x8837E8EB
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0xD254D4C4
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0x019B0111
    call _WhisperMain

_NtSetInformationObject:
    push 0x09353989
    call _WhisperMain

_NtCancelIoFile:
    push 0x18DC005E
    call _WhisperMain

_NtTraceEvent:
    push 0x0B4B4490
    call _WhisperMain

_NtPowerInformation:
    push 0x0A9B0877
    call _WhisperMain

_NtSetValueKey:
    push 0x8703B4BA
    call _WhisperMain

_NtCancelTimer:
    push 0x39A23F32
    call _WhisperMain

_NtSetTimer:
    push 0xC78529DE
    call _WhisperMain

_NtAccessCheckByType:
    push 0xB0292511
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0x06822A55
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0x34DA304C
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0x8BA71195
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0x38AC7100
    call _WhisperMain

_NtAddAtomEx:
    push 0xBD97F163
    call _WhisperMain

_NtAddBootEntry:
    push 0x1D8C071E
    call _WhisperMain

_NtAddDriverEntry:
    push 0x47927D50
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x0C996202
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x3BA57B73
    call _WhisperMain

_NtAlertResumeThread:
    push 0x08A8F586
    call _WhisperMain

_NtAlertThread:
    push 0x22826A21
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0x7521B787
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0xA5BEB609
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x36AF3633
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0xA1A048DA
    call _WhisperMain

_NtAllocateUuids:
    push 0xEC573205
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0x0EEFD8B1
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0x64F25D58
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0xD588D416
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x26F15D1E
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x63EEBFBA
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x50305BAE
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0x36D27407
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x0CA8E4FB
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0x32AB4151
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0xF78AE40D
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0xFAA01B33
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0x850687A8
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x34E4557F
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0x36CE2D46
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x65B1E3AB
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0x20B21AFC
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0x64F4617E
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0x4DE3063C
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x1E8A443F
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x4A5C2941
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0x118B1414
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0xF68FDB2E
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x20B14762
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x1197F084
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0x27A82032
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x7CC0458D
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x1B8F30D0
    call _WhisperMain

_NtCallEnclave:
    push 0x06BA3FE8
    call _WhisperMain

_NtCancelIoFileEx:
    push 0x1882283B
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0x6ABB720C
    call _WhisperMain

_NtCancelTimer2:
    push 0x0B9BEF4D
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0x29AC4170
    call _WhisperMain

_NtCommitComplete:
    push 0xFEB58C6A
    call _WhisperMain

_NtCommitEnlistment:
    push 0x4F157E93
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0xCE48E0D5
    call _WhisperMain

_NtCommitTransaction:
    push 0xD0FA53CE
    call _WhisperMain

_NtCompactKeys:
    push 0x79C07442
    call _WhisperMain

_NtCompareObjects:
    push 0x219C1131
    call _WhisperMain

_NtCompareSigningLevels:
    push 0xE35C1219
    call _WhisperMain

_NtCompareTokens:
    push 0xC5A6D90D
    call _WhisperMain

_NtCompleteConnectPort:
    push 0xEE71FDFE
    call _WhisperMain

_NtCompressKey:
    push 0xC80F266F
    call _WhisperMain

_NtConnectPort:
    push 0x64F07D5E
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x09A0774D
    call _WhisperMain

_NtCreateDebugObject:
    push 0xAC3FACA3
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x0CA42619
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0xACBCEE06
    call _WhisperMain

_NtCreateEnclave:
    push 0x08C62584
    call _WhisperMain

_NtCreateEnlistment:
    push 0x18811F0A
    call _WhisperMain

_NtCreateEventPair:
    push 0x00BDF8CB
    call _WhisperMain

_NtCreateIRTimer:
    push 0x43EF6178
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x8A10AA8F
    call _WhisperMain

_NtCreateJobObject:
    push 0xF8C7D448
    call _WhisperMain

_NtCreateJobSet:
    push 0x0EA21C3D
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0x924E0272
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0xF06AD23C
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0x145112E2
    call _WhisperMain

_NtCreateMailslotFile:
    push 0x26B9F48E
    call _WhisperMain

_NtCreateMutant:
    push 0xC2442229
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x22997A2E
    call _WhisperMain

_NtCreatePagingFile:
    push 0x5EB82864
    call _WhisperMain

_NtCreatePartition:
    push 0xFEA7DCF3
    call _WhisperMain

_NtCreatePort:
    push 0x2EBD1DF2
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x26885D0F
    call _WhisperMain

_NtCreateProcess:
    push 0xE23BFBB7
    call _WhisperMain

_NtCreateProfile:
    push 0x369BFCCA
    call _WhisperMain

_NtCreateProfileEx:
    push 0xCA50092A
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x03B03F1A
    call _WhisperMain

_NtCreateResourceManager:
    push 0x15813F3A
    call _WhisperMain

_NtCreateSemaphore:
    push 0x76985058
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x0AB6200B
    call _WhisperMain

_NtCreateThreadEx:
    push 0x57BB8BFF
    call _WhisperMain

_NtCreateTimer:
    push 0x19DE6356
    call _WhisperMain

_NtCreateTimer2:
    push 0x4FC7CB11
    call _WhisperMain

_NtCreateToken:
    push 0x3D990530
    call _WhisperMain

_NtCreateTokenEx:
    push 0xB8AAF67C
    call _WhisperMain

_NtCreateTransaction:
    push 0x0413C643
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x05B29396
    call _WhisperMain

_NtCreateUserProcess:
    push 0x772F97B2
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0x3D181D4C
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x1C77DE29
    call _WhisperMain

_NtCreateWnfStateName:
    push 0xA514230E
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0xC899F62C
    call _WhisperMain

_NtDebugActiveProcess:
    push 0x01DF6230
    call _WhisperMain

_NtDebugContinue:
    push 0x315E22B6
    call _WhisperMain

_NtDeleteAtom:
    push 0xF22FADE4
    call _WhisperMain

_NtDeleteBootEntry:
    push 0xEBB616C1
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0xC98135F6
    call _WhisperMain

_NtDeleteFile:
    push 0x9244C08C
    call _WhisperMain

_NtDeleteKey:
    push 0xEB5F0535
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x36B73E2A
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x14B0D41D
    call _WhisperMain

_NtDeleteValueKey:
    push 0x86BBF741
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0xD28DF8C6
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0x0CB7D3F7
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0x584904F1
    call _WhisperMain

_NtDisplayString:
    push 0x068E6E0A
    call _WhisperMain

_NtDrawText:
    push 0xFF03C0C9
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0x35A5C8FC
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0xF0A400D8
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x278FA994
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0xB14C0C69
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x16C72875
    call _WhisperMain

_NtExtendSection:
    push 0xF2EF9477
    call _WhisperMain

_NtFilterBootOption:
    push 0x0CA40831
    call _WhisperMain

_NtFilterToken:
    push 0x9BA0F53C
    call _WhisperMain

_NtFilterTokenEx:
    push 0x169A6C78
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0x698724B2
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0x03D5720E
    call _WhisperMain

_NtFlushInstructionCache:
    push 0xBF9B3985
    call _WhisperMain

_NtFlushKey:
    push 0xFB2180C1
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0x3EBC7A6C
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x81188797
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0xCD983AFC
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0x09BE2C2E
    call _WhisperMain

_NtFreezeRegistry:
    push 0x3F5329FD
    call _WhisperMain

_NtFreezeTransactions:
    push 0x079B2B0D
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0x735B09B6
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x0C4A00D7
    call _WhisperMain

_NtGetContextThread:
    push 0x1430D111
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x1A87101A
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0x8A9D2AA6
    call _WhisperMain

_NtGetDevicePowerState:
    push 0x768F782E
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0x5E3E52A3
    call _WhisperMain

_NtGetNextProcess:
    push 0xD79D29F1
    call _WhisperMain

_NtGetNextThread:
    push 0xB290EE20
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0xE757EDCF
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0xB207D8FB
    call _WhisperMain

_NtGetWriteWatch:
    push 0x32FF1662
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x05919C9A
    call _WhisperMain

_NtImpersonateThread:
    push 0x72AA3003
    call _WhisperMain

_NtInitializeEnclave:
    push 0xC25592FE
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0x60D65368
    call _WhisperMain

_NtInitializeRegistry:
    push 0x028E0601
    call _WhisperMain

_NtInitiatePowerAction:
    push 0xDB4C38DD
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0x0A80C7D2
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0x1F8C5523
    call _WhisperMain

_NtListenPort:
    push 0xDA32C7BC
    call _WhisperMain

_NtLoadDriver:
    push 0x4C9F2584
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x83421171
    call _WhisperMain

_NtLoadHotPatch:
    push 0xE0FEEF59
    call _WhisperMain

_NtLoadKey:
    push 0x192E3B77
    call _WhisperMain

_NtLoadKey2:
    push 0x6E3743E8
    call _WhisperMain

_NtLoadKeyEx:
    push 0xDA59E0E4
    call _WhisperMain

_NtLockFile:
    push 0xB9742B43
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0xF389F61F
    call _WhisperMain

_NtLockRegistryKey:
    push 0xD461C7FA
    call _WhisperMain

_NtLockVirtualMemory:
    push 0x0D91191D
    call _WhisperMain

_NtMakePermanentObject:
    push 0xCA949839
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x8AD579BA
    call _WhisperMain

_NtManagePartition:
    push 0x40AA2075
    call _WhisperMain

_NtMapCMFModule:
    push 0xC28E0839
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x459D1E56
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0x0564C018
    call _WhisperMain

_NtModifyBootEntry:
    push 0x0DBB0738
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x0B963CD8
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0x3E197EBE
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0x44A78CD8
    call _WhisperMain

_NtNotifyChangeKey:
    push 0x0E9AC8C5
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x22064DDA
    call _WhisperMain

_NtNotifyChangeSession:
    push 0x0D9F2D10
    call _WhisperMain

_NtOpenEnlistment:
    push 0x17B82813
    call _WhisperMain

_NtOpenEventPair:
    push 0x103038A5
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x548E7459
    call _WhisperMain

_NtOpenJobObject:
    push 0x01980702
    call _WhisperMain

_NtOpenKeyEx:
    push 0x7B95AFCA
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0xA8FB60D7
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0xC42D0677
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0x2E8E3124
    call _WhisperMain

_NtOpenMutant:
    push 0x288A4F18
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x08AE0E3E
    call _WhisperMain

_NtOpenPartition:
    push 0x72A21669
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0x28825B6D
    call _WhisperMain

_NtOpenProcessToken:
    push 0x87365F9C
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x4E800855
    call _WhisperMain

_NtOpenResourceManager:
    push 0x3399071C
    call _WhisperMain

_NtOpenSemaphore:
    push 0x469013A0
    call _WhisperMain

_NtOpenSession:
    push 0xD44DF2DD
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x84B0BC14
    call _WhisperMain

_NtOpenThread:
    push 0xF4A8F800
    call _WhisperMain

_NtOpenTimer:
    push 0x57942716
    call _WhisperMain

_NtOpenTransaction:
    push 0x1E45F059
    call _WhisperMain

_NtOpenTransactionManager:
    push 0x05339316
    call _WhisperMain

_NtPlugPlayControl:
    push 0x907C94D4
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x2CB80836
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0xD6B9FF23
    call _WhisperMain

_NtPrepareComplete:
    push 0xB42E80A4
    call _WhisperMain

_NtPrepareEnlistment:
    push 0x77D95E03
    call _WhisperMain

_NtPrivilegeCheck:
    push 0x06B9190B
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0x4A85BACA
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0xD03ED4A8
    call _WhisperMain

_NtPropagationComplete:
    push 0x2EBBB080
    call _WhisperMain

_NtPropagationFailed:
    push 0x16974428
    call _WhisperMain

_NtPulseEvent:
    push 0x8002F9EC
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0x122575CA
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0xF3F1E155
    call _WhisperMain

_NtQueryBootOptions:
    push 0xDB8918DE
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x1291E890
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0x7657248A
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0x19A1EFDB
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0xA3818135
    call _WhisperMain

_NtQueryEaFile:
    push 0xACFC53A8
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0x94D79573
    call _WhisperMain

_NtQueryInformationAtom:
    push 0xB322BAB9
    call _WhisperMain

_NtQueryInformationByName:
    push 0xFBD1B4FB
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x69D30C25
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0x0CB7F8E8
    call _WhisperMain

_NtQueryInformationPort:
    push 0x9F33BA9B
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0xAD33B19A
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x1B48C70A
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0x19A1436A
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0x18970400
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0x65B76014
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0x2CBEC52C
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x8C9BEC09
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x4EDE4376
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0x3D9CD0FE
    call _WhisperMain

_NtQueryMutant:
    push 0xE4BDE72A
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0xAF28BAA8
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x09874730
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0xC15E3A30
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0xEEBF946F
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0x27923314
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x9EB5A618
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0xACBFB522
    call _WhisperMain

_NtQuerySemaphore:
    push 0x5EC86050
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x183B6CFB
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0xB3B0DA22
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0x5195B0ED
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0x2CDA5628
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x1CF6E2B7
    call _WhisperMain

_NtQueryWnfStateData:
    push 0x18BFFAFC
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0xCC86EE52
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0x8498D246
    call _WhisperMain

_NtRaiseException:
    push 0x08922C47
    call _WhisperMain

_NtRaiseHardError:
    push 0xF9AEFB3F
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0xFA9DD94A
    call _WhisperMain

_NtRecoverEnlistment:
    push 0x76B810A2
    call _WhisperMain

_NtRecoverResourceManager:
    push 0x1B2303A2
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x0DAE7326
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x9687B413
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0x60B00560
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0x305F23D8
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0x308C0C3F
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x7A91BDEE
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x20DDCE8A
    call _WhisperMain

_NtRenameKey:
    push 0x17AD0430
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x2D96E6CC
    call _WhisperMain

_NtReplaceKey:
    push 0x992CFAF0
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0x38BB0038
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0x22B41AF8
    call _WhisperMain

_NtRequestPort:
    push 0x2235399A
    call _WhisperMain

_NtResetEvent:
    push 0xF89BE31C
    call _WhisperMain

_NtResetWriteWatch:
    push 0x64AB683E
    call _WhisperMain

_NtRestoreKey:
    push 0x6B4F0D50
    call _WhisperMain

_NtResumeProcess:
    push 0x4DDB4E44
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0x178C371E
    call _WhisperMain

_NtRollbackComplete:
    push 0x7AA6239A
    call _WhisperMain

_NtRollbackEnlistment:
    push 0x16B0312A
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0x14B67E73
    call _WhisperMain

_NtRollbackTransaction:
    push 0xFE67DEF5
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x9E3DBE8F
    call _WhisperMain

_NtSaveKey:
    push 0x22FD1347
    call _WhisperMain

_NtSaveKeyEx:
    push 0x31BB6764
    call _WhisperMain

_NtSaveMergedKeys:
    push 0xE27CCBDF
    call _WhisperMain

_NtSecureConnectPort:
    push 0x2CA10D7C
    call _WhisperMain

_NtSerializeBoot:
    push 0x292179E4
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0x0F128301
    call _WhisperMain

_NtSetBootOptions:
    push 0x14841A1A
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0xAE21AEBC
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x128F511E
    call _WhisperMain

_NtSetContextThread:
    push 0x923D5C97
    call _WhisperMain

_NtSetDebugFilterState:
    push 0x34CF46D6
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0x24B02D2E
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x022B18AF
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0xBD933DAF
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0x60495CC3
    call _WhisperMain

_NtSetEaFile:
    push 0x63B93B0D
    call _WhisperMain

_NtSetHighEventPair:
    push 0x17B62116
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0xA232A2AB
    call _WhisperMain

_NtSetIRTimer:
    push 0x05CB328A
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x3A87AA8B
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0x5FD57A7F
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x04BC3E31
    call _WhisperMain

_NtSetInformationKey:
    push 0x2CF55107
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0xA3602878
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0x6AFD601C
    call _WhisperMain

_NtSetInformationToken:
    push 0x3005ED36
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x76A37037
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x02A39083
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0xC553EFC1
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0xE4AEE222
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x0C578470
    call _WhisperMain

_NtSetIoCompletion:
    push 0x9649CAE3
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0x40AA8FFD
    call _WhisperMain

_NtSetLdtEntries:
    push 0xB793C473
    call _WhisperMain

_NtSetLowEventPair:
    push 0x5D12BA4B
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0x50D47049
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0x2AA61E30
    call _WhisperMain

_NtSetSecurityObject:
    push 0x12027EF2
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0x4ABAA932
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0x73893534
    call _WhisperMain

_NtSetSystemInformation:
    push 0x1A4A3CDF
    call _WhisperMain

_NtSetSystemPowerState:
    push 0x36B9FC16
    call _WhisperMain

_NtSetSystemTime:
    push 0x20EE2F45
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0x16B40038
    call _WhisperMain

_NtSetTimer2:
    push 0x19429A8F
    call _WhisperMain

_NtSetTimerEx:
    push 0x765BD266
    call _WhisperMain

_NtSetTimerResolution:
    push 0x228DCCD1
    call _WhisperMain

_NtSetUuidSeed:
    push 0x9DA85118
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0x583D32FA
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x0EAC032C
    call _WhisperMain

_NtShutdownSystem:
    push 0x005FD37F
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0x38AF263A
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0x3A99AA95
    call _WhisperMain

_NtSinglePhaseReject:
    push 0xB51E4D73
    call _WhisperMain

_NtStartProfile:
    push 0x8119473B
    call _WhisperMain

_NtStopProfile:
    push 0xE8BDE11B
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x76E4A158
    call _WhisperMain

_NtSuspendProcess:
    push 0xA33DA0A2
    call _WhisperMain

_NtSuspendThread:
    push 0xB885663F
    call _WhisperMain

_NtSystemDebugControl:
    push 0x7FAA0B7D
    call _WhisperMain

_NtTerminateEnclave:
    push 0xE129EFC3
    call _WhisperMain

_NtTerminateJobObject:
    push 0x64DC5E51
    call _WhisperMain

_NtTestAlert:
    push 0x8C979512
    call _WhisperMain

_NtThawRegistry:
    push 0xF05EF4D3
    call _WhisperMain

_NtThawTransactions:
    push 0x3BAB0319
    call _WhisperMain

_NtTraceControl:
    push 0x4D164FFF
    call _WhisperMain

_NtTranslateFilePath:
    push 0x302EDD2A
    call _WhisperMain

_NtUmsThreadYield:
    push 0xF4AACEFC
    call _WhisperMain

_NtUnloadDriver:
    push 0x109B0810
    call _WhisperMain

_NtUnloadKey:
    push 0x685111A1
    call _WhisperMain

_NtUnloadKey2:
    push 0xC9399254
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x5BF01D0E
    call _WhisperMain

_NtUnlockFile:
    push 0x34B33E13
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0xC3952B06
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x8695DA30
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0x3EEF276A
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0xE6B8328E
    call _WhisperMain

_NtVdmControl:
    push 0x099A2D09
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x4DB6692F
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0xF2ADF320
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0x5B3044A2
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0x0E924644
    call _WhisperMain

_NtWaitHighEventPair:
    push 0xA411AC8F
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x4D104387
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x1C84C6CE
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0x03AEEBB2
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0x052D237D
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0xCE93C407
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0x5EC15855
    call _WhisperMain

_NtSavepointTransaction:
    push 0x0E0530A9
    call _WhisperMain

_NtSavepointComplete:
    push 0x56D6B694
    call _WhisperMain

_NtCreateSectionEx:
    push 0xFEAD01DB
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0x38650DDC
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0x508E3B58
    call _WhisperMain

_NtListTransactions:
    push 0x3BA93B03
    call _WhisperMain

_NtMarshallTransaction:
    push 0xF236FAAD
    call _WhisperMain

_NtPullTransaction:
    push 0x1C17FD04
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x3AA2D23A
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x0D962B4D
    call _WhisperMain

_NtStartTm:
    push 0x3D900EDE
    call _WhisperMain

_NtSetInformationProcess:
    push 0xE2462417
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x15805550
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x9A4FB3EE
    call _WhisperMain

_NtQuerySystemTime:
    push 0x74CF7D6B
    call _WhisperMain

_NtManageHotPatch:
    push 0x7E4706A4
    call _WhisperMain

_NtContinueEx:
    push 0x13CF4512
    call _WhisperMain

_RtlCreateUserThread:
    push 0x7CE03635
    call _WhisperMain

