.intel_syntax noprefix
.data
.align 4
stubReturn:     .long 0
returnAddress:  .long 0
espBookmark:    .long 0
syscallNumber:  .long 0
syscallAddress: .long 0

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

.global _WhisperMain

_WhisperMain:
    pop eax                                  
    mov dword ptr [stubReturn], eax         # Save the return address to the stub
    push esp
    pop eax
    add eax, 0x04
    push [eax]
    pop returnAddress                       # Save original return address
    add eax, 0x04
    push eax
    pop espBookmark                         # Save original ESP
    call _SW2_GetSyscallNumber              # Resolve function hash into syscall number
    add esp, 4                              # Restore ESP
    mov dword ptr [syscallNumber], eax      # Save the syscall number
    xor eax, eax
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    je _x86
    inc eax                                 # Inc EAX to 1 for Wow64
_x86:
    push eax                                # Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+0x04]
    call _SW2_GetRandomSyscallAddress       # Get a random 0x02E address
    mov dword ptr [syscallAddress], eax     # Save the address
    mov esp, dword ptr [espBookmark]        # Restore ESP
    mov eax, dword ptr [syscallNumber]      # Restore the syscall number
    call dword ptr syscallAddress           # Call the random syscall location
    mov esp, dword ptr [espBookmark]        # Restore ESP
    push dword ptr [returnAddress]          # Restore the return address
    ret

_NtAccessCheck:
    push 0x18A0737D
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x9BA97DB3
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x68B11B5E
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0x7FEE1137
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x90BFA003
    call _WhisperMain

_NtCallbackReturn:
    push 0x1E941D38
    call _WhisperMain

_NtReadFile:
    push 0xEA79D8E0
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0x7CF8ADCC
    call _WhisperMain

_NtWriteFile:
    push 0x59C9C8FD
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x0E886E1F
    call _WhisperMain

_NtReleaseSemaphore:
    push 0x44960E3A
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x5930A25F
    call _WhisperMain

_NtReplyPort:
    push 0x2EBC2B22
    call _WhisperMain

_NtSetInformationThread:
    push 0x340FF225
    call _WhisperMain

_NtSetEvent:
    push 0x08921512
    call _WhisperMain

_NtClose:
    push 0x4495DDA1
    call _WhisperMain

_NtQueryObject:
    push 0x06286085
    call _WhisperMain

_NtQueryInformationFile:
    push 0x93356B21
    call _WhisperMain

_NtOpenKey:
    push 0x720A7393
    call _WhisperMain

_NtEnumerateValueKey:
    push 0xDA9ADD04
    call _WhisperMain

_NtFindAtom:
    push 0x322317BA
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0x11287BAF
    call _WhisperMain

_NtQueryKey:
    push 0xA672CB80
    call _WhisperMain

_NtQueryValueKey:
    push 0x982089B9
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0xC1512DC6
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x519E7C0E
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x3EAC1F7B
    call _WhisperMain

_NtWriteFileGather:
    push 0x318CE8A7
    call _WhisperMain

_NtCreateKey:
    push 0x104523FE
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x01930F05
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0x396D26E6
    call _WhisperMain

_NtReleaseMutant:
    push 0xBB168A93
    call _WhisperMain

_NtQueryInformationToken:
    push 0x8B9FF70C
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0x20B04558
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0x79917101
    call _WhisperMain

_NtOpenThreadToken:
    push 0xFB531910
    call _WhisperMain

_NtQueryInformationThread:
    push 0x144CD773
    call _WhisperMain

_NtOpenProcess:
    push 0xCE2CC5B1
    call _WhisperMain

_NtSetInformationFile:
    push 0x2D7D51A9
    call _WhisperMain

_NtMapViewOfSection:
    push 0x60C9AE95
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0x30971C08
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0x08E02671
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0x756F27B5
    call _WhisperMain

_NtTerminateProcess:
    push 0xC337DE9E
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0xD88FCC04
    call _WhisperMain

_NtReadFileScatter:
    push 0x05AC0D37
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x5A433EBE
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x64B1500C
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x7BED8581
    call _WhisperMain

_NtEnumerateKey:
    push 0x761F6184
    call _WhisperMain

_NtOpenFile:
    push 0xEA58F2EA
    call _WhisperMain

_NtDelayExecution:
    push 0x1AB51B26
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0xA8E240B0
    call _WhisperMain

_NtQuerySystemInformation:
    push 0x228A241F
    call _WhisperMain

_NtOpenSection:
    push 0x8B23AB8E
    call _WhisperMain

_NtQueryTimer:
    push 0xC99AF150
    call _WhisperMain

_NtFsControlFile:
    push 0x3895E81C
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x9B70CDAF
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x16DB99C4
    call _WhisperMain

_NtDuplicateObject:
    push 0x2C050459
    call _WhisperMain

_NtQueryAttributesFile:
    push 0xA6B5C6B2
    call _WhisperMain

_NtClearEvent:
    push 0x7EA59CF0
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x3191351D
    call _WhisperMain

_NtOpenEvent:
    push 0x183371AE
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0x6DDD5958
    call _WhisperMain

_NtDuplicateToken:
    push 0x8350ADCC
    call _WhisperMain

_NtContinue:
    push 0x2EA07164
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0x55D63014
    call _WhisperMain

_NtQueueApcThread:
    push 0x3CA43609
    call _WhisperMain

_NtYieldExecution:
    push 0x18B23A23
    call _WhisperMain

_NtAddAtom:
    push 0x3FB57C63
    call _WhisperMain

_NtCreateEvent:
    push 0x11B0FFAA
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0x3575CE31
    call _WhisperMain

_NtCreateSection:
    push 0x249304C1
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x1D5C1AC4
    call _WhisperMain

_NtApphelpCacheControl:
    push 0x34624AA3
    call _WhisperMain

_NtCreateProcessEx:
    push 0x11B3E1CB
    call _WhisperMain

_NtCreateThread:
    push 0x922FDC85
    call _WhisperMain

_NtIsProcessInJob:
    push 0xA8D15C80
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0x8792CB57
    call _WhisperMain

_NtQuerySection:
    push 0x1A8C5E27
    call _WhisperMain

_NtResumeThread:
    push 0x6AC0665F
    call _WhisperMain

_NtTerminateThread:
    push 0x2A0B34A9
    call _WhisperMain

_NtReadRequestData:
    push 0x2E83F03C
    call _WhisperMain

_NtCreateFile:
    push 0x6756F762
    call _WhisperMain

_NtQueryEvent:
    push 0x8000E5E6
    call _WhisperMain

_NtWriteRequestData:
    push 0x621E52D0
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x2A353AA9
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0x0C53C00C
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0x51256B89
    call _WhisperMain

_NtSetInformationObject:
    push 0x3C1704BB
    call _WhisperMain

_NtCancelIoFile:
    push 0x08B94C02
    call _WhisperMain

_NtTraceEvent:
    push 0x2EB52126
    call _WhisperMain

_NtPowerInformation:
    push 0x6688641D
    call _WhisperMain

_NtSetValueKey:
    push 0xE9392F67
    call _WhisperMain

_NtCancelTimer:
    push 0x178326C0
    call _WhisperMain

_NtSetTimer:
    push 0x1DC52886
    call _WhisperMain

_NtAccessCheckByType:
    push 0xDC56E104
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0xC972F3DC
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0xC55AC9C5
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0xC85426DF
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0x1683D82A
    call _WhisperMain

_NtAddAtomEx:
    push 0x41A9E191
    call _WhisperMain

_NtAddBootEntry:
    push 0x458B7B2C
    call _WhisperMain

_NtAddDriverEntry:
    push 0x0F972544
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x3D891114
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x7FE55ABD
    call _WhisperMain

_NtAlertResumeThread:
    push 0x1CB2020B
    call _WhisperMain

_NtAlertThread:
    push 0x380734AE
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0x09133583
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0x49AA1A9D
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x3C8415D9
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0xFE65D1FF
    call _WhisperMain

_NtAllocateUuids:
    push 0x110A3997
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0x6C973072
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0x10B1033E
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0x61550348
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x1E8F2520
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x33AE7155
    call _WhisperMain

_NtAlpcCreatePort:
    push 0xE1B28661
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0x4ED3ADC1
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0xFE6AE8DB
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0x42F6634D
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0xFE67EBCE
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0x108A121F
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0x38BCC8D7
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x07AEFAC8
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0xDA41CFE8
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x64F17F5E
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0x3ABF3930
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0xE073EFE8
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0xA1BEB813
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x1CBFD609
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x349C283F
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0x07BAC4E2
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0xD74AC2EB
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x26B63B3E
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x64C9605B
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0xAF96D807
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x0622F45F
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x1CBA4A67
    call _WhisperMain

_NtCallEnclave:
    push 0x2037B507
    call _WhisperMain

_NtCancelIoFileEx:
    push 0x58BA8AE0
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0x397931E9
    call _WhisperMain

_NtCancelTimer2:
    push 0xD794D342
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0x795C1FCE
    call _WhisperMain

_NtCommitComplete:
    push 0x9EC04A8E
    call _WhisperMain

_NtCommitEnlistment:
    push 0x7B258F42
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0x0AE60C77
    call _WhisperMain

_NtCommitTransaction:
    push 0x3AAF0A0D
    call _WhisperMain

_NtCompactKeys:
    push 0x26471BD0
    call _WhisperMain

_NtCompareObjects:
    push 0x49D54157
    call _WhisperMain

_NtCompareSigningLevels:
    push 0x68C56852
    call _WhisperMain

_NtCompareTokens:
    push 0x0D94050F
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x30B2196C
    call _WhisperMain

_NtCompressKey:
    push 0xD0A8E717
    call _WhisperMain

_NtConnectPort:
    push 0x3EB03B22
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x3795DD89
    call _WhisperMain

_NtCreateDebugObject:
    push 0x7AE3022F
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x3AA4760B
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0x42AEB0D4
    call _WhisperMain

_NtCreateEnclave:
    push 0x5A1F9944
    call _WhisperMain

_NtCreateEnlistment:
    push 0x79DC023B
    call _WhisperMain

_NtCreateEventPair:
    push 0x34944A63
    call _WhisperMain

_NtCreateIRTimer:
    push 0x039635D2
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x9C929232
    call _WhisperMain

_NtCreateJobObject:
    push 0x2D6903F3
    call _WhisperMain

_NtCreateJobSet:
    push 0xF3CEDF11
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0x54BC1602
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0x69329245
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0x67D8535A
    call _WhisperMain

_NtCreateMailslotFile:
    push 0x2EBDB48A
    call _WhisperMain

_NtCreateMutant:
    push 0xBE119B48
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x96197812
    call _WhisperMain

_NtCreatePagingFile:
    push 0x74B2026E
    call _WhisperMain

_NtCreatePartition:
    push 0x14825455
    call _WhisperMain

_NtCreatePort:
    push 0x1CB1E5DC
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x4E908625
    call _WhisperMain

_NtCreateProcess:
    push 0x5FDE4E52
    call _WhisperMain

_NtCreateProfile:
    push 0x00DAF080
    call _WhisperMain

_NtCreateProfileEx:
    push 0x805BB2E1
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x1E8E381B
    call _WhisperMain

_NtCreateResourceManager:
    push 0x103302B8
    call _WhisperMain

_NtCreateSemaphore:
    push 0x1D0FC3B4
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x9A26E8CB
    call _WhisperMain

_NtCreateThreadEx:
    push 0x54AA9BDD
    call _WhisperMain

_NtCreateTimer:
    push 0x144622FF
    call _WhisperMain

_NtCreateTimer2:
    push 0xEB52365D
    call _WhisperMain

_NtCreateToken:
    push 0x20482AD1
    call _WhisperMain

_NtCreateTokenEx:
    push 0x8A99CC66
    call _WhisperMain

_NtCreateTransaction:
    push 0x168C3411
    call _WhisperMain

_NtCreateTransactionManager:
    push 0xB22E98B3
    call _WhisperMain

_NtCreateUserProcess:
    push 0x65392CE4
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0x393C3BA2
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x20BD2726
    call _WhisperMain

_NtCreateWnfStateName:
    push 0x1CBECF89
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0x2AA91E26
    call _WhisperMain

_NtDebugActiveProcess:
    push 0x8E248FAB
    call _WhisperMain

_NtDebugContinue:
    push 0x96119E7C
    call _WhisperMain

_NtDeleteAtom:
    push 0xD27FF1E0
    call _WhisperMain

_NtDeleteBootEntry:
    push 0xC99D3CE3
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0xDF9315D0
    call _WhisperMain

_NtDeleteFile:
    push 0xE278ECDC
    call _WhisperMain

_NtDeleteKey:
    push 0x1FAB3208
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0x1897120A
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x1EB55799
    call _WhisperMain

_NtDeleteValueKey:
    push 0xA79A9224
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0x76BC4014
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0x0CC22507
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0xF82FF685
    call _WhisperMain

_NtDisplayString:
    push 0x1E8E2A1E
    call _WhisperMain

_NtDrawText:
    push 0xD24BD7C2
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0x9DCEAD19
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0x4C914109
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x34844D6F
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0x7FD24267
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x6AB56A29
    call _WhisperMain

_NtExtendSection:
    push 0x38A81E21
    call _WhisperMain

_NtFilterBootOption:
    push 0x3A92D781
    call _WhisperMain

_NtFilterToken:
    push 0xE55CD3D8
    call _WhisperMain

_NtFilterTokenEx:
    push 0x0484F1F9
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0x0B9845AE
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0xF557C2CE
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x693F9567
    call _WhisperMain

_NtFlushKey:
    push 0xD461E3DF
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0x7EBC7E2C
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0xB31C89AF
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0x6BC0429B
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0x11BC2A12
    call _WhisperMain

_NtFreezeRegistry:
    push 0x26452CC5
    call _WhisperMain

_NtFreezeTransactions:
    push 0x13CB00AD
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0xB28BB815
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0x44CB0A13
    call _WhisperMain

_NtGetContextThread:
    push 0x6B4E279E
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0x06937878
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0x84EAA254
    call _WhisperMain

_NtGetDevicePowerState:
    push 0xB49BA434
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0x84B7B211
    call _WhisperMain

_NtGetNextProcess:
    push 0x1B9E1E0E
    call _WhisperMain

_NtGetNextThread:
    push 0xEE4B2CED
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0x2B12C80E
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0x823CAA87
    call _WhisperMain

_NtGetWriteWatch:
    push 0x105E2CDA
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x4550AA4A
    call _WhisperMain

_NtImpersonateThread:
    push 0xB000BAAE
    call _WhisperMain

_NtInitializeEnclave:
    push 0x2C93C098
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0x6CECA3B6
    call _WhisperMain

_NtInitializeRegistry:
    push 0xBC533055
    call _WhisperMain

_NtInitiatePowerAction:
    push 0xCB578F84
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0x0440C162
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0x27AA3515
    call _WhisperMain

_NtListenPort:
    push 0xE173E0FD
    call _WhisperMain

_NtLoadDriver:
    push 0x12B81A26
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x849AD429
    call _WhisperMain

_NtLoadHotPatch:
    push 0xECA229FE
    call _WhisperMain

_NtLoadKey:
    push 0x083A69A3
    call _WhisperMain

_NtLoadKey2:
    push 0xAB3221EE
    call _WhisperMain

_NtLoadKeyEx:
    push 0x7399B624
    call _WhisperMain

_NtLockFile:
    push 0x3A3D365A
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0x4F3248A0
    call _WhisperMain

_NtLockRegistryKey:
    push 0xDEABF13D
    call _WhisperMain

_NtLockVirtualMemory:
    push 0x0794EEFB
    call _WhisperMain

_NtMakePermanentObject:
    push 0xA13ECFE4
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x1E3D74A2
    call _WhisperMain

_NtManagePartition:
    push 0x0AE16A33
    call _WhisperMain

_NtMapCMFModule:
    push 0x169B1AFC
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x29B5721E
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0x365CF80A
    call _WhisperMain

_NtModifyBootEntry:
    push 0x099AFCE1
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x21C8CD98
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0xAA3A816E
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0x8B54FFA8
    call _WhisperMain

_NtNotifyChangeKey:
    push 0xF1FBD3A0
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x65BE7236
    call _WhisperMain

_NtNotifyChangeSession:
    push 0x01890314
    call _WhisperMain

_NtOpenEnlistment:
    push 0x5BD55E63
    call _WhisperMain

_NtOpenEventPair:
    push 0x20944861
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x7067F071
    call _WhisperMain

_NtOpenJobObject:
    push 0xF341013F
    call _WhisperMain

_NtOpenKeyEx:
    push 0x0F99C3DC
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0x104416DE
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0x889ABA21
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0xE87FEBE8
    call _WhisperMain

_NtOpenMutant:
    push 0xB22DF5FE
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x2AAD0E7C
    call _WhisperMain

_NtOpenPartition:
    push 0x108DD0DF
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0x785F07BD
    call _WhisperMain

_NtOpenProcessToken:
    push 0xE75BFBEA
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x9CC47B51
    call _WhisperMain

_NtOpenResourceManager:
    push 0xF9512419
    call _WhisperMain

_NtOpenSemaphore:
    push 0x9306CBBB
    call _WhisperMain

_NtOpenSession:
    push 0xD2053455
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x0A943819
    call _WhisperMain

_NtOpenThread:
    push 0x183F5496
    call _WhisperMain

_NtOpenTimer:
    push 0x0B189804
    call _WhisperMain

_NtOpenTransaction:
    push 0x9C089C9B
    call _WhisperMain

_NtOpenTransactionManager:
    push 0x05E791C6
    call _WhisperMain

_NtPlugPlayControl:
    push 0xC6693A38
    call _WhisperMain

_NtPrePrepareComplete:
    push 0x089003FE
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0xF9A71DCC
    call _WhisperMain

_NtPrepareComplete:
    push 0x04D057EE
    call _WhisperMain

_NtPrepareEnlistment:
    push 0xD9469E8D
    call _WhisperMain

_NtPrivilegeCheck:
    push 0x28950FC5
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0xE12EDD61
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0x12B41622
    call _WhisperMain

_NtPropagationComplete:
    push 0x0E913E3A
    call _WhisperMain

_NtPropagationFailed:
    push 0x4ED9AF84
    call _WhisperMain

_NtPulseEvent:
    push 0x000A1B9D
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0xEAD9F64C
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0xF7EEFB75
    call _WhisperMain

_NtQueryBootOptions:
    push 0x178D1F1B
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0x74CA7E6A
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0xC8530A69
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0xE65ACF07
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0x13461DDB
    call _WhisperMain

_NtQueryEaFile:
    push 0xE4A4944F
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0xC6CDC662
    call _WhisperMain

_NtQueryInformationAtom:
    push 0x9B07BA93
    call _WhisperMain

_NtQueryInformationByName:
    push 0xA80AAF91
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x2FB12E23
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0x07A5C2EB
    call _WhisperMain

_NtQueryInformationPort:
    push 0xA73AA8A9
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0x07B6EEEE
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x02ED227F
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0xB32C9DB0
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0xCC9A2E03
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0x4FC9365A
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0xD73B26AF
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x5ED55E47
    call _WhisperMain

_NtQueryLicenseValue:
    push 0xD4433CCC
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0x825AF1A0
    call _WhisperMain

_NtQueryMutant:
    push 0xDE19F380
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0x0DB3606A
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x61DAB182
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x69306CA8
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0xE2B83781
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0x7D27A48C
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x13BCE0C3
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0x05AAE1D7
    call _WhisperMain

_NtQuerySemaphore:
    push 0x3AAA6416
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x1702E100
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0xCA9129DA
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0x534A0796
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0x9694C44E
    call _WhisperMain

_NtQueryTimerResolution:
    push 0xC24DE4D9
    call _WhisperMain

_NtQueryWnfStateData:
    push 0xA3039595
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0xFAEB18E7
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0xFCACFE16
    call _WhisperMain

_NtRaiseException:
    push 0x3F6E1A3D
    call _WhisperMain

_NtRaiseHardError:
    push 0xCF5CD1CD
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0x9236B7A4
    call _WhisperMain

_NtRecoverEnlistment:
    push 0xC8530818
    call _WhisperMain

_NtRecoverResourceManager:
    push 0x605F52FC
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x06379837
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x049326C7
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0xEE76DE3A
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0xDB88FCD3
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0x3E9FE8BB
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x6496A2E8
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0xCA5FCBF4
    call _WhisperMain

_NtRenameKey:
    push 0xE9DF04AC
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x05B75116
    call _WhisperMain

_NtReplaceKey:
    push 0xDD58FCC2
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0xAEAF5BD5
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0xE47EE1EE
    call _WhisperMain

_NtRequestPort:
    push 0xE073F9F6
    call _WhisperMain

_NtResetEvent:
    push 0xDC313C62
    call _WhisperMain

_NtResetWriteWatch:
    push 0x12DF2E5A
    call _WhisperMain

_NtRestoreKey:
    push 0x2BFE4615
    call _WhisperMain

_NtResumeProcess:
    push 0x83D37ABE
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0x0895C8C7
    call _WhisperMain

_NtRollbackComplete:
    push 0x54B85056
    call _WhisperMain

_NtRollbackEnlistment:
    push 0xD9469E8D
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0x10B7F7E2
    call _WhisperMain

_NtRollbackTransaction:
    push 0x03D73B7A
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x0D339D2D
    call _WhisperMain

_NtSaveKey:
    push 0x77CB5654
    call _WhisperMain

_NtSaveKeyEx:
    push 0x1790EBE4
    call _WhisperMain

_NtSaveMergedKeys:
    push 0x25A32A3C
    call _WhisperMain

_NtSecureConnectPort:
    push 0x128D0102
    call _WhisperMain

_NtSerializeBoot:
    push 0x97421756
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0xB16B8BC3
    call _WhisperMain

_NtSetBootOptions:
    push 0x07990D1D
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0x22BB2406
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0x2499AD4E
    call _WhisperMain

_NtSetContextThread:
    push 0x268C2825
    call _WhisperMain

_NtSetDebugFilterState:
    push 0xD749D8ED
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0xFB72E0FD
    call _WhisperMain

_NtSetDefaultLocale:
    push 0xBC24BA98
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0xA40A192F
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0xB7998D35
    call _WhisperMain

_NtSetEaFile:
    push 0xBD2A4348
    call _WhisperMain

_NtSetHighEventPair:
    push 0x44CC405D
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0x50D47445
    call _WhisperMain

_NtSetIRTimer:
    push 0xFF5D1906
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x1C21E44D
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0xC054E1C2
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x8FA0B52E
    call _WhisperMain

_NtSetInformationKey:
    push 0xD859E5FD
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0xE3C7FF6A
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0x6EF76E62
    call _WhisperMain

_NtSetInformationToken:
    push 0x8D088394
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x174BCAE0
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x01B56948
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x19901D1F
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x84509CCE
    call _WhisperMain

_NtSetIntervalProfile:
    push 0xEC263464
    call _WhisperMain

_NtSetIoCompletion:
    push 0xC030E6A5
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0x2695F9C2
    call _WhisperMain

_NtSetLdtEntries:
    push 0x8CA4FF44
    call _WhisperMain

_NtSetLowEventPair:
    push 0x11923702
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0x04DC004D
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0x9E3DA8AE
    call _WhisperMain

_NtSetSecurityObject:
    push 0xD847888B
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0x1E88F888
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0x1C0124BE
    call _WhisperMain

_NtSetSystemInformation:
    push 0xD9B6DF25
    call _WhisperMain

_NtSetSystemPowerState:
    push 0xD950A7D2
    call _WhisperMain

_NtSetSystemTime:
    push 0x3EAB4F3F
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0x8204E480
    call _WhisperMain

_NtSetTimer2:
    push 0x9BD89B16
    call _WhisperMain

_NtSetTimerEx:
    push 0xB54085F8
    call _WhisperMain

_NtSetTimerResolution:
    push 0x54C27455
    call _WhisperMain

_NtSetUuidSeed:
    push 0x7458C176
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0x1EBFD488
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x1288F19E
    call _WhisperMain

_NtShutdownSystem:
    push 0xCCEDF547
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0xC452D8B7
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0xA63B9E97
    call _WhisperMain

_NtSinglePhaseReject:
    push 0x223C44CF
    call _WhisperMain

_NtStartProfile:
    push 0x815AD3EF
    call _WhisperMain

_NtStopProfile:
    push 0x049DCAB8
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x9E39D3E0
    call _WhisperMain

_NtSuspendProcess:
    push 0x315E32C0
    call _WhisperMain

_NtSuspendThread:
    push 0x36932821
    call _WhisperMain

_NtSystemDebugControl:
    push 0x019FF3D9
    call _WhisperMain

_NtTerminateEnclave:
    push 0x60BF7434
    call _WhisperMain

_NtTerminateJobObject:
    push 0x049F5245
    call _WhisperMain

_NtTestAlert:
    push 0xCF52DAF3
    call _WhisperMain

_NtThawRegistry:
    push 0xC2A133E8
    call _WhisperMain

_NtThawTransactions:
    push 0x77E74B55
    call _WhisperMain

_NtTraceControl:
    push 0x3FA9F9F3
    call _WhisperMain

_NtTranslateFilePath:
    push 0xFF56FCCD
    call _WhisperMain

_NtUmsThreadYield:
    push 0x8F159CA1
    call _WhisperMain

_NtUnloadDriver:
    push 0xDD6A2061
    call _WhisperMain

_NtUnloadKey:
    push 0x68BD075B
    call _WhisperMain

_NtUnloadKey2:
    push 0x33D56F58
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x29E71F58
    call _WhisperMain

_NtUnlockFile:
    push 0x2A7B5CEF
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0xFFA8C917
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x4A914E2C
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0xEA3FB7FE
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0xCD02DFB3
    call _WhisperMain

_NtVdmControl:
    push 0x8B9012A6
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x46BA6C7D
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0x00CF1D66
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0x90CA6AAD
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0xF8AED47B
    call _WhisperMain

_NtWaitHighEventPair:
    push 0xD34FC1D0
    call _WhisperMain

_NtWaitLowEventPair:
    push 0xB4165C0B
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x6AD32A5C
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0xF7BC10D7
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0xC089E259
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0xF56929C7
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0xD843FA97
    call _WhisperMain

_NtSavepointTransaction:
    push 0x9813DAC7
    call _WhisperMain

_NtSavepointComplete:
    push 0x88DA86B3
    call _WhisperMain

_NtCreateSectionEx:
    push 0xB053F2E9
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0xFE3CC196
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0x00902D08
    call _WhisperMain

_NtListTransactions:
    push 0x8525A983
    call _WhisperMain

_NtMarshallTransaction:
    push 0x905B92CF
    call _WhisperMain

_NtPullTransaction:
    push 0x900BD6DB
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x8E15828E
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0xDC8FDA1C
    call _WhisperMain

_NtStartTm:
    push 0x031E49A0
    call _WhisperMain

_NtSetInformationProcess:
    push 0x8117868C
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x359314C2
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x9801A1BC
    call _WhisperMain

_NtQuerySystemTime:
    push 0xB9A357A9
    call _WhisperMain

_NtManageHotPatch:
    push 0xA0BF2EA8
    call _WhisperMain

_NtContinueEx:
    push 0x5FC5BBB9
    call _WhisperMain

