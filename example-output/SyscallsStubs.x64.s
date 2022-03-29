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
    mov dword ptr [currentHash], 0x0B6D641BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWorkerFactoryWorkerReady:
    mov dword ptr [currentHash], 0x0163E3285   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcceptConnectPort:
    mov dword ptr [currentHash], 0x02EB72D38   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPagesScatter:
    mov dword ptr [currentHash], 0x0D19E1AC6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForSingleObject:
    mov dword ptr [currentHash], 0x018A02BEF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallbackReturn:
    mov dword ptr [currentHash], 0x0829013BE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFile:
    mov dword ptr [currentHash], 0x028C05C56   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeviceIoControlFile:
    mov dword ptr [currentHash], 0x0D841A2A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFile:
    mov dword ptr [currentHash], 0x0C9719FCB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletion:
    mov dword ptr [currentHash], 0x016801617   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseSemaphore:
    mov dword ptr [currentHash], 0x01457341A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePort:
    mov dword ptr [currentHash], 0x07AB26F32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyPort:
    mov dword ptr [currentHash], 0x0DA342B5A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationThread:
    mov dword ptr [currentHash], 0x02A8E6857   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEvent:
    mov dword ptr [currentHash], 0x0CB020C49   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClose:
    mov dword ptr [currentHash], 0x046D16D51   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryObject:
    mov dword ptr [currentHash], 0x01F3075CE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationFile:
    mov dword ptr [currentHash], 0x085115D55   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKey:
    mov dword ptr [currentHash], 0x02490F9CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateValueKey:
    mov dword ptr [currentHash], 0x019CD7426   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFindAtom:
    mov dword ptr [currentHash], 0x038AD2144   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultLocale:
    mov dword ptr [currentHash], 0x0C221CCB2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryKey:
    mov dword ptr [currentHash], 0x03BE15A1A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryValueKey:
    mov dword ptr [currentHash], 0x01C1D1F87   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemory:
    mov dword ptr [currentHash], 0x03191457D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationProcess:
    mov dword ptr [currentHash], 0x0832D80A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects32:
    mov dword ptr [currentHash], 0x0C85C2D8B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFileGather:
    mov dword ptr [currentHash], 0x0379E6D37   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKey:
    mov dword ptr [currentHash], 0x039002E90   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeVirtualMemory:
    mov dword ptr [currentHash], 0x001990F0F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateClientOfPort:
    mov dword ptr [currentHash], 0x058F16D58   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseMutant:
    mov dword ptr [currentHash], 0x0BF1C984F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationToken:
    mov dword ptr [currentHash], 0x0939DD948   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWaitReplyPort:
    mov dword ptr [currentHash], 0x038B1235E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVirtualMemory:
    mov dword ptr [currentHash], 0x033AE1F39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadToken:
    mov dword ptr [currentHash], 0x01DA027EC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationThread:
    mov dword ptr [currentHash], 0x0B207F4A5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcess:
    mov dword ptr [currentHash], 0x0EAA8F120   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationFile:
    mov dword ptr [currentHash], 0x0725AB909   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSection:
    mov dword ptr [currentHash], 0x022CC205D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckAndAuditAlarm:
    mov dword ptr [currentHash], 0x0DABDE4F0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSection:
    mov dword ptr [currentHash], 0x0D28DF657   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePortEx:
    mov dword ptr [currentHash], 0x0AF8072D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateProcess:
    mov dword ptr [currentHash], 0x077BF5E26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEventBoostPriority:
    mov dword ptr [currentHash], 0x022B3ADB4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFileScatter:
    mov dword ptr [currentHash], 0x0058C0D17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadTokenEx:
    mov dword ptr [currentHash], 0x0BA4FC4B9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessTokenEx:
    mov dword ptr [currentHash], 0x038AA7A50   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPerformanceCounter:
    mov dword ptr [currentHash], 0x02B89C793   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateKey:
    mov dword ptr [currentHash], 0x07ECF5E94   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenFile:
    mov dword ptr [currentHash], 0x0E77EEFEB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDelayExecution:
    mov dword ptr [currentHash], 0x0C20DE25F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFile:
    mov dword ptr [currentHash], 0x03F38BD21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformation:
    mov dword ptr [currentHash], 0x0EFB51AD7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSection:
    mov dword ptr [currentHash], 0x0DFB2FB39   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimer:
    mov dword ptr [currentHash], 0x03C16F04C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFsControlFile:
    mov dword ptr [currentHash], 0x0C94297F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteVirtualMemory:
    mov dword ptr [currentHash], 0x00B970317   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCloseObjectAuditAlarm:
    mov dword ptr [currentHash], 0x010BFECF0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateObject:
    mov dword ptr [currentHash], 0x008B62A2B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAttributesFile:
    mov dword ptr [currentHash], 0x09DDBBC81   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearEvent:
    mov dword ptr [currentHash], 0x0704ABB1C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadVirtualMemory:
    mov dword ptr [currentHash], 0x001910F07   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEvent:
    mov dword ptr [currentHash], 0x0004D07C6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustPrivilegesToken:
    mov dword ptr [currentHash], 0x09449F4DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateToken:
    mov dword ptr [currentHash], 0x00B9EFF06   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinue:
    mov dword ptr [currentHash], 0x0D55BEACF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultUILanguage:
    mov dword ptr [currentHash], 0x09233B5AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThread:
    mov dword ptr [currentHash], 0x036822C3B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtYieldExecution:
    mov dword ptr [currentHash], 0x060CA061F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtom:
    mov dword ptr [currentHash], 0x0964EF75C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEvent:
    mov dword ptr [currentHash], 0x000BD7B4A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVolumeInformationFile:
    mov dword ptr [currentHash], 0x064C05C66   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSection:
    mov dword ptr [currentHash], 0x03E911CDD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFile:
    mov dword ptr [currentHash], 0x07CAB2E9E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtApphelpCacheControl:
    mov dword ptr [currentHash], 0x00FD80B43   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcessEx:
    mov dword ptr [currentHash], 0x08F8FCD34   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThread:
    mov dword ptr [currentHash], 0x076D96C6F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsProcessInJob:
    mov dword ptr [currentHash], 0x029933921   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtProtectVirtualMemory:
    mov dword ptr [currentHash], 0x099F38567   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySection:
    mov dword ptr [currentHash], 0x0E04BE6DF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeThread:
    mov dword ptr [currentHash], 0x094AD1E8B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateThread:
    mov dword ptr [currentHash], 0x050800A31   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadRequestData:
    mov dword ptr [currentHash], 0x0C608DEB2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateFile:
    mov dword ptr [currentHash], 0x0D87CA29C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEvent:
    mov dword ptr [currentHash], 0x031746CDC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteRequestData:
    mov dword ptr [currentHash], 0x036BA0E24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenDirectoryObject:
    mov dword ptr [currentHash], 0x00BAB657A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeAndAuditAlarm:
    mov dword ptr [currentHash], 0x05B357D66   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects:
    mov dword ptr [currentHash], 0x0F75ADF07   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationObject:
    mov dword ptr [currentHash], 0x004985645   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFile:
    mov dword ptr [currentHash], 0x0B8BB5EBF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceEvent:
    mov dword ptr [currentHash], 0x042864312   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPowerInformation:
    mov dword ptr [currentHash], 0x0ED4BEBD8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetValueKey:
    mov dword ptr [currentHash], 0x02AFC0D63   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer:
    mov dword ptr [currentHash], 0x08B9FFB1D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer:
    mov dword ptr [currentHash], 0x09CA9F453   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByType:
    mov dword ptr [currentHash], 0x0B72E5D20   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultList:
    mov dword ptr [currentHash], 0x050C2100F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword ptr [currentHash], 0x01ABC1024   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword ptr [currentHash], 0x0C04DF8DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireProcessActivityReference:
    mov dword ptr [currentHash], 0x07ACB6B7E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtomEx:
    mov dword ptr [currentHash], 0x0E1132F46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddBootEntry:
    mov dword ptr [currentHash], 0x049947D28   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddDriverEntry:
    mov dword ptr [currentHash], 0x047D2736E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustGroupsToken:
    mov dword ptr [currentHash], 0x01F988590   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustTokenClaimsAndDeviceGroups:
    mov dword ptr [currentHash], 0x03D973D01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertResumeThread:
    mov dword ptr [currentHash], 0x05CCEDEEF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThread:
    mov dword ptr [currentHash], 0x020985A45   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThreadByThreadId:
    mov dword ptr [currentHash], 0x09CA377E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateLocallyUniqueId:
    mov dword ptr [currentHash], 0x0378A9940   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateReserveObject:
    mov dword ptr [currentHash], 0x0391729BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUserPhysicalPages:
    mov dword ptr [currentHash], 0x05FBE7024   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUuids:
    mov dword ptr [currentHash], 0x04E575ECB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemoryEx:
    mov dword ptr [currentHash], 0x076EFA8B9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcAcceptConnectPort:
    mov dword ptr [currentHash], 0x0ACF19342   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCancelMessage:
    mov dword ptr [currentHash], 0x08DDE9967   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPort:
    mov dword ptr [currentHash], 0x0A0BE1DB0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPortEx:
    mov dword ptr [currentHash], 0x03D0F71CB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePort:
    mov dword ptr [currentHash], 0x022B33D38   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePortSection:
    mov dword ptr [currentHash], 0x006AA263F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateResourceReserve:
    mov dword ptr [currentHash], 0x01A9E1E7F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSectionView:
    mov dword ptr [currentHash], 0x0D048B9D7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSecurityContext:
    mov dword ptr [currentHash], 0x056C94B58   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeletePortSection:
    mov dword ptr [currentHash], 0x036AD10F9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteResourceReserve:
    mov dword ptr [currentHash], 0x0F761E7CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSectionView:
    mov dword ptr [currentHash], 0x0049C293B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSecurityContext:
    mov dword ptr [currentHash], 0x09CC79146   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDisconnectPort:
    mov dword ptr [currentHash], 0x0593058BE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientContainerOfPort:
    mov dword ptr [currentHash], 0x0FE760D38   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientOfPort:
    mov dword ptr [currentHash], 0x0A93184AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderProcess:
    mov dword ptr [currentHash], 0x0C557C6C8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderThread:
    mov dword ptr [currentHash], 0x09427D601   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformation:
    mov dword ptr [currentHash], 0x03CAE4643   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformationMessage:
    mov dword ptr [currentHash], 0x093B15C90   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcRevokeSecurityContext:
    mov dword ptr [currentHash], 0x0772A826B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSendWaitReceivePort:
    mov dword ptr [currentHash], 0x0E1720463   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSetInformation:
    mov dword ptr [currentHash], 0x000A80239   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAreMappedFilesTheSame:
    mov dword ptr [currentHash], 0x09734447C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssignProcessToJobObject:
    mov dword ptr [currentHash], 0x01C800A1D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssociateWaitCompletionPacket:
    mov dword ptr [currentHash], 0x0098D2332   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallEnclave:
    mov dword ptr [currentHash], 0x01AAC6E46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFileEx:
    mov dword ptr [currentHash], 0x0D8052A7F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelSynchronousIoFile:
    mov dword ptr [currentHash], 0x038AFEC1C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer2:
    mov dword ptr [currentHash], 0x096143ACA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelWaitCompletionPacket:
    mov dword ptr [currentHash], 0x0BB9CC350   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitComplete:
    mov dword ptr [currentHash], 0x0AA35FCFE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitEnlistment:
    mov dword ptr [currentHash], 0x0D76AECDD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitRegistryTransaction:
    mov dword ptr [currentHash], 0x00F980302   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitTransaction:
    mov dword ptr [currentHash], 0x0B329F1F8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompactKeys:
    mov dword ptr [currentHash], 0x0C3A5FE0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareObjects:
    mov dword ptr [currentHash], 0x0039D0313   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareSigningLevels:
    mov dword ptr [currentHash], 0x0D043D6D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareTokens:
    mov dword ptr [currentHash], 0x043C3495B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompleteConnectPort:
    mov dword ptr [currentHash], 0x020B52F36   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompressKey:
    mov dword ptr [currentHash], 0x098CAA368   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConnectPort:
    mov dword ptr [currentHash], 0x066BF195C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword ptr [currentHash], 0x02B97BF95   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDebugObject:
    mov dword ptr [currentHash], 0x00CA1645D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObject:
    mov dword ptr [currentHash], 0x009A1FFDB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObjectEx:
    mov dword ptr [currentHash], 0x0F6790F3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnclave:
    mov dword ptr [currentHash], 0x016300A8A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnlistment:
    mov dword ptr [currentHash], 0x06BA72A6D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEventPair:
    mov dword ptr [currentHash], 0x00757F637   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIRTimer:
    mov dword ptr [currentHash], 0x07B996D02   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIoCompletion:
    mov dword ptr [currentHash], 0x052C8725F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobObject:
    mov dword ptr [currentHash], 0x096BDAE11   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobSet:
    mov dword ptr [currentHash], 0x082C28450   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyTransacted:
    mov dword ptr [currentHash], 0x0ECA3351E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyedEvent:
    mov dword ptr [currentHash], 0x0E05DDBFA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateLowBoxToken:
    mov dword ptr [currentHash], 0x015349407   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMailslotFile:
    mov dword ptr [currentHash], 0x0E97ED3D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMutant:
    mov dword ptr [currentHash], 0x07E9E1C88   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateNamedPipeFile:
    mov dword ptr [currentHash], 0x085031D03   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePagingFile:
    mov dword ptr [currentHash], 0x06AFA5BAE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePartition:
    mov dword ptr [currentHash], 0x036AC163B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePort:
    mov dword ptr [currentHash], 0x0DC4EBFD0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePrivateNamespace:
    mov dword ptr [currentHash], 0x096B2AD2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcess:
    mov dword ptr [currentHash], 0x0272D24A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfile:
    mov dword ptr [currentHash], 0x0F4DDEB67   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfileEx:
    mov dword ptr [currentHash], 0x005BBD0E7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateRegistryTransaction:
    mov dword ptr [currentHash], 0x09F87DF55   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateResourceManager:
    mov dword ptr [currentHash], 0x0BB62C3A8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSemaphore:
    mov dword ptr [currentHash], 0x0109BF8D6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSymbolicLinkObject:
    mov dword ptr [currentHash], 0x00B24F92A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThreadEx:
    mov dword ptr [currentHash], 0x098B757F1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer:
    mov dword ptr [currentHash], 0x09CB7962C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer2:
    mov dword ptr [currentHash], 0x0B02BEFA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateToken:
    mov dword ptr [currentHash], 0x084AD920E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTokenEx:
    mov dword ptr [currentHash], 0x020A25258   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransaction:
    mov dword ptr [currentHash], 0x0E237DA9D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransactionManager:
    mov dword ptr [currentHash], 0x019A136F0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateUserProcess:
    mov dword ptr [currentHash], 0x0EDA3CE3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitCompletionPacket:
    mov dword ptr [currentHash], 0x0073D77C1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitablePort:
    mov dword ptr [currentHash], 0x02871CA1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWnfStateName:
    mov dword ptr [currentHash], 0x0B4BA5BB1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWorkerFactory:
    mov dword ptr [currentHash], 0x0DCCDF265   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugActiveProcess:
    mov dword ptr [currentHash], 0x07E3197AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugContinue:
    mov dword ptr [currentHash], 0x058D98B96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteAtom:
    mov dword ptr [currentHash], 0x0AD5F2C4D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteBootEntry:
    mov dword ptr [currentHash], 0x00D951502   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteDriverEntry:
    mov dword ptr [currentHash], 0x0CA96DE0B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteFile:
    mov dword ptr [currentHash], 0x014B3DE16   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteKey:
    mov dword ptr [currentHash], 0x069D34464   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteObjectAuditAlarm:
    mov dword ptr [currentHash], 0x074DA8FD6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeletePrivateNamespace:
    mov dword ptr [currentHash], 0x01CAD3F35   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteValueKey:
    mov dword ptr [currentHash], 0x0C51D1046   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateData:
    mov dword ptr [currentHash], 0x0134B3F87   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateName:
    mov dword ptr [currentHash], 0x08A8D871D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisableLastKnownGood:
    mov dword ptr [currentHash], 0x015CB8BF0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisplayString:
    mov dword ptr [currentHash], 0x068909F00   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDrawText:
    mov dword ptr [currentHash], 0x0D34AD0DD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnableLastKnownGood:
    mov dword ptr [currentHash], 0x06BF90732   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateBootEntries:
    mov dword ptr [currentHash], 0x00E963B09   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateDriverEntries:
    mov dword ptr [currentHash], 0x02C96B699   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateSystemEnvironmentValuesEx:
    mov dword ptr [currentHash], 0x0D19DE521   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateTransactionObject:
    mov dword ptr [currentHash], 0x00C90361D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtExtendSection:
    mov dword ptr [currentHash], 0x0128A3019   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterBootOption:
    mov dword ptr [currentHash], 0x00EA60E33   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterToken:
    mov dword ptr [currentHash], 0x0C355ADCA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterTokenEx:
    mov dword ptr [currentHash], 0x0769F2A4A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFileEx:
    mov dword ptr [currentHash], 0x0A634616A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstallUILanguage:
    mov dword ptr [currentHash], 0x00FD14672   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstructionCache:
    mov dword ptr [currentHash], 0x04D9BB1DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushKey:
    mov dword ptr [currentHash], 0x019CEE8B6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushProcessWriteBuffers:
    mov dword ptr [currentHash], 0x079399F6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushVirtualMemory:
    mov dword ptr [currentHash], 0x03FA90907   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushWriteBuffer:
    mov dword ptr [currentHash], 0x0802BDAE2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeUserPhysicalPages:
    mov dword ptr [currentHash], 0x07BE16462   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeRegistry:
    mov dword ptr [currentHash], 0x00E6A100F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeTransactions:
    mov dword ptr [currentHash], 0x00F4A05DD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCachedSigningLevel:
    mov dword ptr [currentHash], 0x0969A1DA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCompleteWnfStateSubscription:
    mov dword ptr [currentHash], 0x04C922453   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetContextThread:
    mov dword ptr [currentHash], 0x054D01671   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumber:
    mov dword ptr [currentHash], 0x09A3B8A99   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumberEx:
    mov dword ptr [currentHash], 0x086A2C25E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetDevicePowerState:
    mov dword ptr [currentHash], 0x036893E26   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetMUIRegistryInfo:
    mov dword ptr [currentHash], 0x0FC74C8F1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextProcess:
    mov dword ptr [currentHash], 0x0863B9757   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextThread:
    mov dword ptr [currentHash], 0x08A895136   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNlsSectionPtr:
    mov dword ptr [currentHash], 0x02292AB8D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNotificationResourceManager:
    mov dword ptr [currentHash], 0x00F3F1194   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetWriteWatch:
    mov dword ptr [currentHash], 0x0B779F9CF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateAnonymousToken:
    mov dword ptr [currentHash], 0x00794898C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateThread:
    mov dword ptr [currentHash], 0x081A8C174   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeEnclave:
    mov dword ptr [currentHash], 0x0883AB77E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeNlsFiles:
    mov dword ptr [currentHash], 0x0FEDEC97A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeRegistry:
    mov dword ptr [currentHash], 0x0198AF1DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitiatePowerAction:
    mov dword ptr [currentHash], 0x008922A07   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsSystemResumeAutomatic:
    mov dword ptr [currentHash], 0x022BA5568   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsUILanguageComitted:
    mov dword ptr [currentHash], 0x07BA27317   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListenPort:
    mov dword ptr [currentHash], 0x020B3CF28   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadDriver:
    mov dword ptr [currentHash], 0x0945DFE86   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadEnclaveData:
    mov dword ptr [currentHash], 0x06342B777   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadHotPatch:
    mov dword ptr [currentHash], 0x090AEA036   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey:
    mov dword ptr [currentHash], 0x069209848   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey2:
    mov dword ptr [currentHash], 0x02149CB54   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKeyEx:
    mov dword ptr [currentHash], 0x063681596   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockFile:
    mov dword ptr [currentHash], 0x02D74AB69   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockProductActivationKeys:
    mov dword ptr [currentHash], 0x022C03565   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockRegistryKey:
    mov dword ptr [currentHash], 0x07621558E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockVirtualMemory:
    mov dword ptr [currentHash], 0x019916919   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakePermanentObject:
    mov dword ptr [currentHash], 0x022BC2C21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakeTemporaryObject:
    mov dword ptr [currentHash], 0x006984055   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManagePartition:
    mov dword ptr [currentHash], 0x019743BA5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapCMFModule:
    mov dword ptr [currentHash], 0x03EF510A6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPages:
    mov dword ptr [currentHash], 0x02F9E5E62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSectionEx:
    mov dword ptr [currentHash], 0x002917268   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyBootEntry:
    mov dword ptr [currentHash], 0x0B9F575A0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyDriverEntry:
    mov dword ptr [currentHash], 0x019820116   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFile:
    mov dword ptr [currentHash], 0x0EED4AFF2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFileEx:
    mov dword ptr [currentHash], 0x0C92793F2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeKey:
    mov dword ptr [currentHash], 0x028142F8B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeMultipleKeys:
    mov dword ptr [currentHash], 0x023B92826   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeSession:
    mov dword ptr [currentHash], 0x0018EEF92   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEnlistment:
    mov dword ptr [currentHash], 0x089D34C85   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEventPair:
    mov dword ptr [currentHash], 0x010B3DCED   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenIoCompletion:
    mov dword ptr [currentHash], 0x036A9163B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenJobObject:
    mov dword ptr [currentHash], 0x008B4D919   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyEx:
    mov dword ptr [currentHash], 0x04D5A9906   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransacted:
    mov dword ptr [currentHash], 0x0B55EF5E3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransactedEx:
    mov dword ptr [currentHash], 0x026BD7460   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyedEvent:
    mov dword ptr [currentHash], 0x046CC615E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenMutant:
    mov dword ptr [currentHash], 0x0E8B7F13A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenObjectAuditAlarm:
    mov dword ptr [currentHash], 0x0DB5ADFCD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPartition:
    mov dword ptr [currentHash], 0x0CE912CC5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPrivateNamespace:
    mov dword ptr [currentHash], 0x0AA8EB728   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessToken:
    mov dword ptr [currentHash], 0x0B3ED8D40   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenRegistryTransaction:
    mov dword ptr [currentHash], 0x01572C81D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenResourceManager:
    mov dword ptr [currentHash], 0x0C71FEFA6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSemaphore:
    mov dword ptr [currentHash], 0x0709E5A5E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSession:
    mov dword ptr [currentHash], 0x0DA909A42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSymbolicLinkObject:
    mov dword ptr [currentHash], 0x00C91040D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThread:
    mov dword ptr [currentHash], 0x0EECCF26F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTimer:
    mov dword ptr [currentHash], 0x08D249BC0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransaction:
    mov dword ptr [currentHash], 0x0CEC5EA57   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransactionManager:
    mov dword ptr [currentHash], 0x0C415D4B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPlugPlayControl:
    mov dword ptr [currentHash], 0x08E108A88   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareComplete:
    mov dword ptr [currentHash], 0x0054071AC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareEnlistment:
    mov dword ptr [currentHash], 0x0CB55CEC3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareComplete:
    mov dword ptr [currentHash], 0x038B6D025   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareEnlistment:
    mov dword ptr [currentHash], 0x030274DD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeCheck:
    mov dword ptr [currentHash], 0x0C25DF1C1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeObjectAuditAlarm:
    mov dword ptr [currentHash], 0x09334726B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegedServiceAuditAlarm:
    mov dword ptr [currentHash], 0x01AA5F2FA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationComplete:
    mov dword ptr [currentHash], 0x015343DF4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationFailed:
    mov dword ptr [currentHash], 0x019B69D96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPulseEvent:
    mov dword ptr [currentHash], 0x030AC153C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAuxiliaryCounterFrequency:
    mov dword ptr [currentHash], 0x078CC82CD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootEntryOrder:
    mov dword ptr [currentHash], 0x06C3178D0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootOptions:
    mov dword ptr [currentHash], 0x04C1B6285   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDebugFilterState:
    mov dword ptr [currentHash], 0x076CF1C40   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFileEx:
    mov dword ptr [currentHash], 0x00A1946AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryObject:
    mov dword ptr [currentHash], 0x0EC48C0F3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDriverEntryOrder:
    mov dword ptr [currentHash], 0x00B2E75C3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEaFile:
    mov dword ptr [currentHash], 0x038987C42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryFullAttributesFile:
    mov dword ptr [currentHash], 0x0B0BA5EB2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationAtom:
    mov dword ptr [currentHash], 0x051C3B257   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationByName:
    mov dword ptr [currentHash], 0x0FADDD389   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationEnlistment:
    mov dword ptr [currentHash], 0x00395320F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationJobObject:
    mov dword ptr [currentHash], 0x004B82DE5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationPort:
    mov dword ptr [currentHash], 0x09932B2AD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationResourceManager:
    mov dword ptr [currentHash], 0x0EBD3B9F3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransaction:
    mov dword ptr [currentHash], 0x01ED41C79   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransactionManager:
    mov dword ptr [currentHash], 0x035B76176   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationWorkerFactory:
    mov dword ptr [currentHash], 0x0254E0FEC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInstallUILanguage:
    mov dword ptr [currentHash], 0x0CF5CF80C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIntervalProfile:
    mov dword ptr [currentHash], 0x0A061F6DC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIoCompletion:
    mov dword ptr [currentHash], 0x01BB51EDE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryLicenseValue:
    mov dword ptr [currentHash], 0x03A3F29B4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMultipleValueKey:
    mov dword ptr [currentHash], 0x0ED24D096   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMutant:
    mov dword ptr [currentHash], 0x07E965F42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeys:
    mov dword ptr [currentHash], 0x08294ED4E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeysEx:
    mov dword ptr [currentHash], 0x077DBA48F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPortInformationProcess:
    mov dword ptr [currentHash], 0x019B4241C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryQuotaInformationFile:
    mov dword ptr [currentHash], 0x0BCBBB61F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityAttributesToken:
    mov dword ptr [currentHash], 0x0FC66E4CD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityObject:
    mov dword ptr [currentHash], 0x0EFBD8563   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityPolicy:
    mov dword ptr [currentHash], 0x0045FF92B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySemaphore:
    mov dword ptr [currentHash], 0x0CD5F32C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySymbolicLinkObject:
    mov dword ptr [currentHash], 0x0132B3377   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValue:
    mov dword ptr [currentHash], 0x04CBB7764   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValueEx:
    mov dword ptr [currentHash], 0x023DEEF9A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformationEx:
    mov dword ptr [currentHash], 0x0697D29B5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimerResolution:
    mov dword ptr [currentHash], 0x01E816402   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateData:
    mov dword ptr [currentHash], 0x0AC0E8282   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateNameInformation:
    mov dword ptr [currentHash], 0x09A4BFC9F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThreadEx:
    mov dword ptr [currentHash], 0x098B9269E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseException:
    mov dword ptr [currentHash], 0x001A8217A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseHardError:
    mov dword ptr [currentHash], 0x009978393   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadOnlyEnlistment:
    mov dword ptr [currentHash], 0x0EEA1CF33   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverEnlistment:
    mov dword ptr [currentHash], 0x011933405   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverResourceManager:
    mov dword ptr [currentHash], 0x04D905F0C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverTransactionManager:
    mov dword ptr [currentHash], 0x082B5B60F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterProtocolAddressInformation:
    mov dword ptr [currentHash], 0x0D54EF51C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterThreadTerminatePort:
    mov dword ptr [currentHash], 0x066F67F62   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseKeyedEvent:
    mov dword ptr [currentHash], 0x008890F12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseWorkerFactoryWorker:
    mov dword ptr [currentHash], 0x0BC8D8A29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletionEx:
    mov dword ptr [currentHash], 0x0B49732A8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveProcessDebug:
    mov dword ptr [currentHash], 0x01050FE46   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameKey:
    mov dword ptr [currentHash], 0x01B0C46D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameTransactionManager:
    mov dword ptr [currentHash], 0x02FA9E7F0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplaceKey:
    mov dword ptr [currentHash], 0x066CE7554   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplacePartitionUnit:
    mov dword ptr [currentHash], 0x022BE3E1E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReplyPort:
    mov dword ptr [currentHash], 0x024B42B2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestPort:
    mov dword ptr [currentHash], 0x0A0374F24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetEvent:
    mov dword ptr [currentHash], 0x044CE8F88   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetWriteWatch:
    mov dword ptr [currentHash], 0x0FCE9375A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRestoreKey:
    mov dword ptr [currentHash], 0x0FB3EE7A5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeProcess:
    mov dword ptr [currentHash], 0x011A90C20   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRevertContainerImpersonation:
    mov dword ptr [currentHash], 0x0C629C4C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackComplete:
    mov dword ptr [currentHash], 0x059204DCC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackEnlistment:
    mov dword ptr [currentHash], 0x031872C15   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackRegistryTransaction:
    mov dword ptr [currentHash], 0x0CA51CAC3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackTransaction:
    mov dword ptr [currentHash], 0x09CBDDA69   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollforwardTransactionManager:
    mov dword ptr [currentHash], 0x003AF9F82   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKey:
    mov dword ptr [currentHash], 0x03BAF2A30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKeyEx:
    mov dword ptr [currentHash], 0x09798D324   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveMergedKeys:
    mov dword ptr [currentHash], 0x067827A6C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSecureConnectPort:
    mov dword ptr [currentHash], 0x0983281BC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSerializeBoot:
    mov dword ptr [currentHash], 0x0CBD8D946   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootEntryOrder:
    mov dword ptr [currentHash], 0x0960E8E84   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootOptions:
    mov dword ptr [currentHash], 0x0779C2F4B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel:
    mov dword ptr [currentHash], 0x0AABA3194   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel2:
    mov dword ptr [currentHash], 0x03E10D901   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetContextThread:
    mov dword ptr [currentHash], 0x0AB9BA70B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDebugFilterState:
    mov dword ptr [currentHash], 0x0B3316903   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultHardErrorPort:
    mov dword ptr [currentHash], 0x0A734A0BF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultLocale:
    mov dword ptr [currentHash], 0x0452D7FEB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultUILanguage:
    mov dword ptr [currentHash], 0x0299B6E3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDriverEntryOrder:
    mov dword ptr [currentHash], 0x013A51131   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEaFile:
    mov dword ptr [currentHash], 0x0C0FA48C8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighEventPair:
    mov dword ptr [currentHash], 0x0D753F5CC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighWaitLowEventPair:
    mov dword ptr [currentHash], 0x03F6ECE0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIRTimer:
    mov dword ptr [currentHash], 0x00850DB12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationDebugObject:
    mov dword ptr [currentHash], 0x08837B8BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationEnlistment:
    mov dword ptr [currentHash], 0x0479B3A4D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationJobObject:
    mov dword ptr [currentHash], 0x08ED07ACF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationKey:
    mov dword ptr [currentHash], 0x0C2785060   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationResourceManager:
    mov dword ptr [currentHash], 0x0C41FD0BD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationSymbolicLink:
    mov dword ptr [currentHash], 0x0A8A67607   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationToken:
    mov dword ptr [currentHash], 0x063D6755E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransaction:
    mov dword ptr [currentHash], 0x01681381D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransactionManager:
    mov dword ptr [currentHash], 0x005349715   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationVirtualMemory:
    mov dword ptr [currentHash], 0x09B028F9F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationWorkerFactory:
    mov dword ptr [currentHash], 0x0786D108F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIntervalProfile:
    mov dword ptr [currentHash], 0x076A1B0F8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletion:
    mov dword ptr [currentHash], 0x002D843F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletionEx:
    mov dword ptr [currentHash], 0x0C92F0C73   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLdtEntries:
    mov dword ptr [currentHash], 0x05B6A2499   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowEventPair:
    mov dword ptr [currentHash], 0x040D27C5B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowWaitHighEventPair:
    mov dword ptr [currentHash], 0x0A43DA4A3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetQuotaInformationFile:
    mov dword ptr [currentHash], 0x0A23B5420   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSecurityObject:
    mov dword ptr [currentHash], 0x0FAD676B9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValue:
    mov dword ptr [currentHash], 0x01C9F0B0C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValueEx:
    mov dword ptr [currentHash], 0x00F935D4E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemInformation:
    mov dword ptr [currentHash], 0x0072F4385   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemPowerState:
    mov dword ptr [currentHash], 0x010892602   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemTime:
    mov dword ptr [currentHash], 0x03EAD353D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetThreadExecutionState:
    mov dword ptr [currentHash], 0x012B3ECA8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer2:
    mov dword ptr [currentHash], 0x0CF356FAB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerEx:
    mov dword ptr [currentHash], 0x01CFA2E40   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerResolution:
    mov dword ptr [currentHash], 0x054CE745D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetUuidSeed:
    mov dword ptr [currentHash], 0x01DCF5F12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetVolumeInformationFile:
    mov dword ptr [currentHash], 0x03402BB21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetWnfProcessNotificationEvent:
    mov dword ptr [currentHash], 0x016CB77DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownSystem:
    mov dword ptr [currentHash], 0x0C0ECECB7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownWorkerFactory:
    mov dword ptr [currentHash], 0x0189320D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSignalAndWaitForSingleObject:
    mov dword ptr [currentHash], 0x029111FA8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSinglePhaseReject:
    mov dword ptr [currentHash], 0x0249E3611   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartProfile:
    mov dword ptr [currentHash], 0x060356B93   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStopProfile:
    mov dword ptr [currentHash], 0x0E5B21DE6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSubscribeWnfStateChange:
    mov dword ptr [currentHash], 0x006A77F3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendProcess:
    mov dword ptr [currentHash], 0x077AB5232   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendThread:
    mov dword ptr [currentHash], 0x01CBD5E1B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSystemDebugControl:
    mov dword ptr [currentHash], 0x0BDAC5CBA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateEnclave:
    mov dword ptr [currentHash], 0x0613E59E2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateJobObject:
    mov dword ptr [currentHash], 0x01EA037FD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTestAlert:
    mov dword ptr [currentHash], 0x08CAFE33C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawRegistry:
    mov dword ptr [currentHash], 0x03EAC3439   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawTransactions:
    mov dword ptr [currentHash], 0x0900AF0DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceControl:
    mov dword ptr [currentHash], 0x0B865DEF4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTranslateFilePath:
    mov dword ptr [currentHash], 0x0F2B2CFE7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUmsThreadYield:
    mov dword ptr [currentHash], 0x009B78290   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadDriver:
    mov dword ptr [currentHash], 0x09CD7A65B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey:
    mov dword ptr [currentHash], 0x05B2C58B5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey2:
    mov dword ptr [currentHash], 0x0EE7706E9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKeyEx:
    mov dword ptr [currentHash], 0x03F99C3E2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockFile:
    mov dword ptr [currentHash], 0x0E1781BFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockVirtualMemory:
    mov dword ptr [currentHash], 0x00F98213F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSectionEx:
    mov dword ptr [currentHash], 0x040DA1604   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnsubscribeWnfStateChange:
    mov dword ptr [currentHash], 0x0209C6524   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUpdateWnfStateData:
    mov dword ptr [currentHash], 0x00C851638   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtVdmControl:
    mov dword ptr [currentHash], 0x01BC3E185   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForAlertByThreadId:
    mov dword ptr [currentHash], 0x06CABA912   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForDebugEvent:
    mov dword ptr [currentHash], 0x0968A759C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForKeyedEvent:
    mov dword ptr [currentHash], 0x0F918FC89   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWorkViaWorkerFactory:
    mov dword ptr [currentHash], 0x0489E7A52   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitHighEventPair:
    mov dword ptr [currentHash], 0x023332BA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitLowEventPair:
    mov dword ptr [currentHash], 0x072DF924D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireCMFViewOwnership:
    mov dword ptr [currentHash], 0x00B4D01D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelDeviceWakeupRequest:
    mov dword ptr [currentHash], 0x0D421DCA5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearAllSavepointsTransaction:
    mov dword ptr [currentHash], 0x09E05BE8B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearSavepointTransaction:
    mov dword ptr [currentHash], 0x0FD69C1A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackSavepointTransaction:
    mov dword ptr [currentHash], 0x01C47DE17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointTransaction:
    mov dword ptr [currentHash], 0x01C844249   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointComplete:
    mov dword ptr [currentHash], 0x01A90361A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSectionEx:
    mov dword ptr [currentHash], 0x0984DC69B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateCrossVmEvent:
    mov dword ptr [currentHash], 0x0C951D0DF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetPlugPlayEvent:
    mov dword ptr [currentHash], 0x0E0452617   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListTransactions:
    mov dword ptr [currentHash], 0x0ECB6E62C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMarshallTransaction:
    mov dword ptr [currentHash], 0x07ADD647D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPullTransaction:
    mov dword ptr [currentHash], 0x07D557FF9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseCMFViewOwnership:
    mov dword ptr [currentHash], 0x05A6F42F8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWnfNotifications:
    mov dword ptr [currentHash], 0x00D992ACB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartTm:
    mov dword ptr [currentHash], 0x0C38E50AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationProcess:
    mov dword ptr [currentHash], 0x06DAF4A7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestDeviceWakeup:
    mov dword ptr [currentHash], 0x05517B042   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWakeupLatency:
    mov dword ptr [currentHash], 0x0043EE142   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemTime:
    mov dword ptr [currentHash], 0x0EAAEF31B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManageHotPatch:
    mov dword ptr [currentHash], 0x0F0D1E66E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinueEx:
    mov dword ptr [currentHash], 0x02794F0CB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


RtlCreateUserThread:
    mov dword ptr [currentHash], 0x016AE441F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


