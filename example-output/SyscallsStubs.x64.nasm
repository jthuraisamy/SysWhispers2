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
    mov dword [currentHash], 0B6D641BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWorkerFactoryWorkerReady:
    mov dword [currentHash], 0163E3285h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcceptConnectPort:
    mov dword [currentHash], 02EB72D38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPagesScatter:
    mov dword [currentHash], 0D19E1AC6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForSingleObject:
    mov dword [currentHash], 018A02BEFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallbackReturn:
    mov dword [currentHash], 0829013BEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFile:
    mov dword [currentHash], 028C05C56h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeviceIoControlFile:
    mov dword [currentHash], 0D841A2A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFile:
    mov dword [currentHash], 0C9719FCBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletion:
    mov dword [currentHash], 016801617h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseSemaphore:
    mov dword [currentHash], 01457341Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePort:
    mov dword [currentHash], 07AB26F32h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyPort:
    mov dword [currentHash], 0DA342B5Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationThread:
    mov dword [currentHash], 02A8E6857h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEvent:
    mov dword [currentHash], 0CB020C49h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClose:
    mov dword [currentHash], 046D16D51h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryObject:
    mov dword [currentHash], 01F3075CEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationFile:
    mov dword [currentHash], 085115D55h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKey:
    mov dword [currentHash], 02490F9CAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateValueKey:
    mov dword [currentHash], 019CD7426h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFindAtom:
    mov dword [currentHash], 038AD2144h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultLocale:
    mov dword [currentHash], 0C221CCB2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryKey:
    mov dword [currentHash], 03BE15A1Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryValueKey:
    mov dword [currentHash], 01C1D1F87h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemory:
    mov dword [currentHash], 03191457Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationProcess:
    mov dword [currentHash], 0832D80A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects32:
    mov dword [currentHash], 0C85C2D8Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteFileGather:
    mov dword [currentHash], 0379E6D37h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKey:
    mov dword [currentHash], 039002E90h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeVirtualMemory:
    mov dword [currentHash], 001990F0Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateClientOfPort:
    mov dword [currentHash], 058F16D58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseMutant:
    mov dword [currentHash], 0BF1C984Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationToken:
    mov dword [currentHash], 0939DD948h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWaitReplyPort:
    mov dword [currentHash], 038B1235Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVirtualMemory:
    mov dword [currentHash], 033AE1F39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadToken:
    mov dword [currentHash], 01DA027ECh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationThread:
    mov dword [currentHash], 0B207F4A5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcess:
    mov dword [currentHash], 0EAA8F120h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationFile:
    mov dword [currentHash], 0725AB909h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSection:
    mov dword [currentHash], 022CC205Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckAndAuditAlarm:
    mov dword [currentHash], 0DABDE4F0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSection:
    mov dword [currentHash], 0D28DF657h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReceivePortEx:
    mov dword [currentHash], 0AF8072D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateProcess:
    mov dword [currentHash], 077BF5E26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEventBoostPriority:
    mov dword [currentHash], 022B3ADB4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadFileScatter:
    mov dword [currentHash], 0058C0D17h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThreadTokenEx:
    mov dword [currentHash], 0BA4FC4B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessTokenEx:
    mov dword [currentHash], 038AA7A50h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPerformanceCounter:
    mov dword [currentHash], 02B89C793h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateKey:
    mov dword [currentHash], 07ECF5E94h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenFile:
    mov dword [currentHash], 0E77EEFEBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDelayExecution:
    mov dword [currentHash], 0C20DE25Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFile:
    mov dword [currentHash], 03F38BD21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformation:
    mov dword [currentHash], 0EFB51AD7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSection:
    mov dword [currentHash], 0DFB2FB39h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimer:
    mov dword [currentHash], 03C16F04Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFsControlFile:
    mov dword [currentHash], 0C94297F7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 00B970317h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCloseObjectAuditAlarm:
    mov dword [currentHash], 010BFECF0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateObject:
    mov dword [currentHash], 008B62A2Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAttributesFile:
    mov dword [currentHash], 09DDBBC81h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearEvent:
    mov dword [currentHash], 0704ABB1Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadVirtualMemory:
    mov dword [currentHash], 001910F07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEvent:
    mov dword [currentHash], 0004D07C6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustPrivilegesToken:
    mov dword [currentHash], 09449F4DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDuplicateToken:
    mov dword [currentHash], 00B9EFF06h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinue:
    mov dword [currentHash], 0D55BEACFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDefaultUILanguage:
    mov dword [currentHash], 09233B5AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThread:
    mov dword [currentHash], 036822C3Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtYieldExecution:
    mov dword [currentHash], 060CA061Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtom:
    mov dword [currentHash], 0964EF75Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEvent:
    mov dword [currentHash], 000BD7B4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryVolumeInformationFile:
    mov dword [currentHash], 064C05C66h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSection:
    mov dword [currentHash], 03E911CDDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFile:
    mov dword [currentHash], 07CAB2E9Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtApphelpCacheControl:
    mov dword [currentHash], 00FD80B43h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcessEx:
    mov dword [currentHash], 08F8FCD34h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThread:
    mov dword [currentHash], 076D96C6Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsProcessInJob:
    mov dword [currentHash], 029933921h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtProtectVirtualMemory:
    mov dword [currentHash], 099F38567h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySection:
    mov dword [currentHash], 0E04BE6DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeThread:
    mov dword [currentHash], 094AD1E8Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateThread:
    mov dword [currentHash], 050800A31h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadRequestData:
    mov dword [currentHash], 0C608DEB2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateFile:
    mov dword [currentHash], 0D87CA29Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEvent:
    mov dword [currentHash], 031746CDCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteRequestData:
    mov dword [currentHash], 036BA0E24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenDirectoryObject:
    mov dword [currentHash], 00BAB657Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeAndAuditAlarm:
    mov dword [currentHash], 05B357D66h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForMultipleObjects:
    mov dword [currentHash], 0F75ADF07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationObject:
    mov dword [currentHash], 004985645h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFile:
    mov dword [currentHash], 0B8BB5EBFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceEvent:
    mov dword [currentHash], 042864312h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPowerInformation:
    mov dword [currentHash], 0ED4BEBD8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetValueKey:
    mov dword [currentHash], 02AFC0D63h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer:
    mov dword [currentHash], 08B9FFB1Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer:
    mov dword [currentHash], 09CA9F453h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByType:
    mov dword [currentHash], 0B72E5D20h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultList:
    mov dword [currentHash], 050C2100Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword [currentHash], 01ABC1024h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword [currentHash], 0C04DF8DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireProcessActivityReference:
    mov dword [currentHash], 07ACB6B7Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddAtomEx:
    mov dword [currentHash], 0E1132F46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddBootEntry:
    mov dword [currentHash], 049947D28h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAddDriverEntry:
    mov dword [currentHash], 047D2736Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustGroupsToken:
    mov dword [currentHash], 01F988590h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAdjustTokenClaimsAndDeviceGroups:
    mov dword [currentHash], 03D973D01h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertResumeThread:
    mov dword [currentHash], 05CCEDEEFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThread:
    mov dword [currentHash], 020985A45h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlertThreadByThreadId:
    mov dword [currentHash], 09CA377E5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateLocallyUniqueId:
    mov dword [currentHash], 0378A9940h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateReserveObject:
    mov dword [currentHash], 0391729BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUserPhysicalPages:
    mov dword [currentHash], 05FBE7024h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateUuids:
    mov dword [currentHash], 04E575ECBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemoryEx:
    mov dword [currentHash], 076EFA8B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcAcceptConnectPort:
    mov dword [currentHash], 0ACF19342h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCancelMessage:
    mov dword [currentHash], 08DDE9967h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPort:
    mov dword [currentHash], 0A0BE1DB0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcConnectPortEx:
    mov dword [currentHash], 03D0F71CBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePort:
    mov dword [currentHash], 022B33D38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreatePortSection:
    mov dword [currentHash], 006AA263Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateResourceReserve:
    mov dword [currentHash], 01A9E1E7Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSectionView:
    mov dword [currentHash], 0D048B9D7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcCreateSecurityContext:
    mov dword [currentHash], 056C94B58h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeletePortSection:
    mov dword [currentHash], 036AD10F9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteResourceReserve:
    mov dword [currentHash], 0F761E7CAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSectionView:
    mov dword [currentHash], 0049C293Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDeleteSecurityContext:
    mov dword [currentHash], 09CC79146h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcDisconnectPort:
    mov dword [currentHash], 0593058BEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientContainerOfPort:
    mov dword [currentHash], 0FE760D38h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcImpersonateClientOfPort:
    mov dword [currentHash], 0A93184AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderProcess:
    mov dword [currentHash], 0C557C6C8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcOpenSenderThread:
    mov dword [currentHash], 09427D601h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformation:
    mov dword [currentHash], 03CAE4643h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcQueryInformationMessage:
    mov dword [currentHash], 093B15C90h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcRevokeSecurityContext:
    mov dword [currentHash], 0772A826Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSendWaitReceivePort:
    mov dword [currentHash], 0E1720463h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAlpcSetInformation:
    mov dword [currentHash], 000A80239h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAreMappedFilesTheSame:
    mov dword [currentHash], 09734447Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssignProcessToJobObject:
    mov dword [currentHash], 01C800A1Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAssociateWaitCompletionPacket:
    mov dword [currentHash], 0098D2332h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCallEnclave:
    mov dword [currentHash], 01AAC6E46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelIoFileEx:
    mov dword [currentHash], 0D8052A7Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelSynchronousIoFile:
    mov dword [currentHash], 038AFEC1Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelTimer2:
    mov dword [currentHash], 096143ACAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelWaitCompletionPacket:
    mov dword [currentHash], 0BB9CC350h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitComplete:
    mov dword [currentHash], 0AA35FCFEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitEnlistment:
    mov dword [currentHash], 0D76AECDDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitRegistryTransaction:
    mov dword [currentHash], 00F980302h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCommitTransaction:
    mov dword [currentHash], 0B329F1F8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompactKeys:
    mov dword [currentHash], 0C3A5FE0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareObjects:
    mov dword [currentHash], 0039D0313h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareSigningLevels:
    mov dword [currentHash], 0D043D6D8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompareTokens:
    mov dword [currentHash], 043C3495Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompleteConnectPort:
    mov dword [currentHash], 020B52F36h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCompressKey:
    mov dword [currentHash], 098CAA368h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConnectPort:
    mov dword [currentHash], 066BF195Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword [currentHash], 02B97BF95h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDebugObject:
    mov dword [currentHash], 00CA1645Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObject:
    mov dword [currentHash], 009A1FFDBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateDirectoryObjectEx:
    mov dword [currentHash], 0F6790F3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnclave:
    mov dword [currentHash], 016300A8Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEnlistment:
    mov dword [currentHash], 06BA72A6Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateEventPair:
    mov dword [currentHash], 00757F637h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIRTimer:
    mov dword [currentHash], 07B996D02h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateIoCompletion:
    mov dword [currentHash], 052C8725Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobObject:
    mov dword [currentHash], 096BDAE11h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateJobSet:
    mov dword [currentHash], 082C28450h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyTransacted:
    mov dword [currentHash], 0ECA3351Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateKeyedEvent:
    mov dword [currentHash], 0E05DDBFAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateLowBoxToken:
    mov dword [currentHash], 015349407h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMailslotFile:
    mov dword [currentHash], 0E97ED3D9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateMutant:
    mov dword [currentHash], 07E9E1C88h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateNamedPipeFile:
    mov dword [currentHash], 085031D03h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePagingFile:
    mov dword [currentHash], 06AFA5BAEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePartition:
    mov dword [currentHash], 036AC163Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePort:
    mov dword [currentHash], 0DC4EBFD0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreatePrivateNamespace:
    mov dword [currentHash], 096B2AD2Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProcess:
    mov dword [currentHash], 0272D24A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfile:
    mov dword [currentHash], 0F4DDEB67h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateProfileEx:
    mov dword [currentHash], 005BBD0E7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateRegistryTransaction:
    mov dword [currentHash], 09F87DF55h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateResourceManager:
    mov dword [currentHash], 0BB62C3A8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSemaphore:
    mov dword [currentHash], 0109BF8D6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSymbolicLinkObject:
    mov dword [currentHash], 00B24F92Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 098B757F1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer:
    mov dword [currentHash], 09CB7962Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTimer2:
    mov dword [currentHash], 0B02BEFA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateToken:
    mov dword [currentHash], 084AD920Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTokenEx:
    mov dword [currentHash], 020A25258h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransaction:
    mov dword [currentHash], 0E237DA9Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateTransactionManager:
    mov dword [currentHash], 019A136F0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateUserProcess:
    mov dword [currentHash], 0EDA3CE3Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitCompletionPacket:
    mov dword [currentHash], 0073D77C1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWaitablePort:
    mov dword [currentHash], 02871CA1Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWnfStateName:
    mov dword [currentHash], 0B4BA5BB1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateWorkerFactory:
    mov dword [currentHash], 0DCCDF265h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugActiveProcess:
    mov dword [currentHash], 07E3197ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDebugContinue:
    mov dword [currentHash], 058D98B96h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteAtom:
    mov dword [currentHash], 0AD5F2C4Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteBootEntry:
    mov dword [currentHash], 00D951502h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteDriverEntry:
    mov dword [currentHash], 0CA96DE0Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteFile:
    mov dword [currentHash], 014B3DE16h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteKey:
    mov dword [currentHash], 069D34464h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteObjectAuditAlarm:
    mov dword [currentHash], 074DA8FD6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeletePrivateNamespace:
    mov dword [currentHash], 01CAD3F35h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteValueKey:
    mov dword [currentHash], 0C51D1046h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateData:
    mov dword [currentHash], 0134B3F87h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDeleteWnfStateName:
    mov dword [currentHash], 08A8D871Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisableLastKnownGood:
    mov dword [currentHash], 015CB8BF0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDisplayString:
    mov dword [currentHash], 068909F00h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtDrawText:
    mov dword [currentHash], 0D34AD0DDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnableLastKnownGood:
    mov dword [currentHash], 06BF90732h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateBootEntries:
    mov dword [currentHash], 00E963B09h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateDriverEntries:
    mov dword [currentHash], 02C96B699h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateSystemEnvironmentValuesEx:
    mov dword [currentHash], 0D19DE521h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtEnumerateTransactionObject:
    mov dword [currentHash], 00C90361Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtExtendSection:
    mov dword [currentHash], 0128A3019h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterBootOption:
    mov dword [currentHash], 00EA60E33h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterToken:
    mov dword [currentHash], 0C355ADCAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFilterTokenEx:
    mov dword [currentHash], 0769F2A4Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushBuffersFileEx:
    mov dword [currentHash], 0A634616Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstallUILanguage:
    mov dword [currentHash], 00FD14672h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushInstructionCache:
    mov dword [currentHash], 04D9BB1DBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushKey:
    mov dword [currentHash], 019CEE8B6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushProcessWriteBuffers:
    mov dword [currentHash], 079399F6Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushVirtualMemory:
    mov dword [currentHash], 03FA90907h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFlushWriteBuffer:
    mov dword [currentHash], 0802BDAE2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreeUserPhysicalPages:
    mov dword [currentHash], 07BE16462h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeRegistry:
    mov dword [currentHash], 00E6A100Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtFreezeTransactions:
    mov dword [currentHash], 00F4A05DDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCachedSigningLevel:
    mov dword [currentHash], 0969A1DA4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCompleteWnfStateSubscription:
    mov dword [currentHash], 04C922453h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetContextThread:
    mov dword [currentHash], 054D01671h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumber:
    mov dword [currentHash], 09A3B8A99h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetCurrentProcessorNumberEx:
    mov dword [currentHash], 086A2C25Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetDevicePowerState:
    mov dword [currentHash], 036893E26h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetMUIRegistryInfo:
    mov dword [currentHash], 0FC74C8F1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextProcess:
    mov dword [currentHash], 0863B9757h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNextThread:
    mov dword [currentHash], 08A895136h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNlsSectionPtr:
    mov dword [currentHash], 02292AB8Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetNotificationResourceManager:
    mov dword [currentHash], 00F3F1194h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetWriteWatch:
    mov dword [currentHash], 0B779F9CFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateAnonymousToken:
    mov dword [currentHash], 00794898Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtImpersonateThread:
    mov dword [currentHash], 081A8C174h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeEnclave:
    mov dword [currentHash], 0883AB77Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeNlsFiles:
    mov dword [currentHash], 0FEDEC97Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitializeRegistry:
    mov dword [currentHash], 0198AF1DAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtInitiatePowerAction:
    mov dword [currentHash], 008922A07h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsSystemResumeAutomatic:
    mov dword [currentHash], 022BA5568h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtIsUILanguageComitted:
    mov dword [currentHash], 07BA27317h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListenPort:
    mov dword [currentHash], 020B3CF28h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadDriver:
    mov dword [currentHash], 0945DFE86h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadEnclaveData:
    mov dword [currentHash], 06342B777h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadHotPatch:
    mov dword [currentHash], 090AEA036h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey:
    mov dword [currentHash], 069209848h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKey2:
    mov dword [currentHash], 02149CB54h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLoadKeyEx:
    mov dword [currentHash], 063681596h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockFile:
    mov dword [currentHash], 02D74AB69h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockProductActivationKeys:
    mov dword [currentHash], 022C03565h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockRegistryKey:
    mov dword [currentHash], 07621558Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtLockVirtualMemory:
    mov dword [currentHash], 019916919h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakePermanentObject:
    mov dword [currentHash], 022BC2C21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMakeTemporaryObject:
    mov dword [currentHash], 006984055h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManagePartition:
    mov dword [currentHash], 019743BA5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapCMFModule:
    mov dword [currentHash], 03EF510A6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapUserPhysicalPages:
    mov dword [currentHash], 02F9E5E62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMapViewOfSectionEx:
    mov dword [currentHash], 002917268h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyBootEntry:
    mov dword [currentHash], 0B9F575A0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtModifyDriverEntry:
    mov dword [currentHash], 019820116h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFile:
    mov dword [currentHash], 0EED4AFF2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeDirectoryFileEx:
    mov dword [currentHash], 0C92793F2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeKey:
    mov dword [currentHash], 028142F8Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeMultipleKeys:
    mov dword [currentHash], 023B92826h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtNotifyChangeSession:
    mov dword [currentHash], 0018EEF92h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEnlistment:
    mov dword [currentHash], 089D34C85h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenEventPair:
    mov dword [currentHash], 010B3DCEDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenIoCompletion:
    mov dword [currentHash], 036A9163Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenJobObject:
    mov dword [currentHash], 008B4D919h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyEx:
    mov dword [currentHash], 04D5A9906h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransacted:
    mov dword [currentHash], 0B55EF5E3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyTransactedEx:
    mov dword [currentHash], 026BD7460h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenKeyedEvent:
    mov dword [currentHash], 046CC615Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenMutant:
    mov dword [currentHash], 0E8B7F13Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenObjectAuditAlarm:
    mov dword [currentHash], 0DB5ADFCDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPartition:
    mov dword [currentHash], 0CE912CC5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenPrivateNamespace:
    mov dword [currentHash], 0AA8EB728h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenProcessToken:
    mov dword [currentHash], 0B3ED8D40h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenRegistryTransaction:
    mov dword [currentHash], 01572C81Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenResourceManager:
    mov dword [currentHash], 0C71FEFA6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSemaphore:
    mov dword [currentHash], 0709E5A5Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSession:
    mov dword [currentHash], 0DA909A42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenSymbolicLinkObject:
    mov dword [currentHash], 00C91040Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenThread:
    mov dword [currentHash], 0EECCF26Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTimer:
    mov dword [currentHash], 08D249BC0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransaction:
    mov dword [currentHash], 0CEC5EA57h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtOpenTransactionManager:
    mov dword [currentHash], 0C415D4B7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPlugPlayControl:
    mov dword [currentHash], 08E108A88h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareComplete:
    mov dword [currentHash], 0054071ACh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrePrepareEnlistment:
    mov dword [currentHash], 0CB55CEC3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareComplete:
    mov dword [currentHash], 038B6D025h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrepareEnlistment:
    mov dword [currentHash], 030274DD5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeCheck:
    mov dword [currentHash], 0C25DF1C1h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegeObjectAuditAlarm:
    mov dword [currentHash], 09334726Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPrivilegedServiceAuditAlarm:
    mov dword [currentHash], 01AA5F2FAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationComplete:
    mov dword [currentHash], 015343DF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPropagationFailed:
    mov dword [currentHash], 019B69D96h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPulseEvent:
    mov dword [currentHash], 030AC153Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryAuxiliaryCounterFrequency:
    mov dword [currentHash], 078CC82CDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootEntryOrder:
    mov dword [currentHash], 06C3178D0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryBootOptions:
    mov dword [currentHash], 04C1B6285h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDebugFilterState:
    mov dword [currentHash], 076CF1C40h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryFileEx:
    mov dword [currentHash], 00A1946ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDirectoryObject:
    mov dword [currentHash], 0EC48C0F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryDriverEntryOrder:
    mov dword [currentHash], 00B2E75C3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryEaFile:
    mov dword [currentHash], 038987C42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryFullAttributesFile:
    mov dword [currentHash], 0B0BA5EB2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationAtom:
    mov dword [currentHash], 051C3B257h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationByName:
    mov dword [currentHash], 0FADDD389h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationEnlistment:
    mov dword [currentHash], 00395320Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationJobObject:
    mov dword [currentHash], 004B82DE5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationPort:
    mov dword [currentHash], 09932B2ADh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationResourceManager:
    mov dword [currentHash], 0EBD3B9F3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransaction:
    mov dword [currentHash], 01ED41C79h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationTransactionManager:
    mov dword [currentHash], 035B76176h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInformationWorkerFactory:
    mov dword [currentHash], 0254E0FECh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryInstallUILanguage:
    mov dword [currentHash], 0CF5CF80Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIntervalProfile:
    mov dword [currentHash], 0A061F6DCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryIoCompletion:
    mov dword [currentHash], 01BB51EDEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryLicenseValue:
    mov dword [currentHash], 03A3F29B4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMultipleValueKey:
    mov dword [currentHash], 0ED24D096h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryMutant:
    mov dword [currentHash], 07E965F42h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeys:
    mov dword [currentHash], 08294ED4Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryOpenSubKeysEx:
    mov dword [currentHash], 077DBA48Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryPortInformationProcess:
    mov dword [currentHash], 019B4241Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryQuotaInformationFile:
    mov dword [currentHash], 0BCBBB61Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityAttributesToken:
    mov dword [currentHash], 0FC66E4CDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityObject:
    mov dword [currentHash], 0EFBD8563h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySecurityPolicy:
    mov dword [currentHash], 0045FF92Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySemaphore:
    mov dword [currentHash], 0CD5F32C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySymbolicLinkObject:
    mov dword [currentHash], 0132B3377h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValue:
    mov dword [currentHash], 04CBB7764h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemEnvironmentValueEx:
    mov dword [currentHash], 023DEEF9Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemInformationEx:
    mov dword [currentHash], 0697D29B5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryTimerResolution:
    mov dword [currentHash], 01E816402h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateData:
    mov dword [currentHash], 0AC0E8282h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueryWnfStateNameInformation:
    mov dword [currentHash], 09A4BFC9Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQueueApcThreadEx:
    mov dword [currentHash], 098B9269Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseException:
    mov dword [currentHash], 001A8217Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRaiseHardError:
    mov dword [currentHash], 009978393h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReadOnlyEnlistment:
    mov dword [currentHash], 0EEA1CF33h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverEnlistment:
    mov dword [currentHash], 011933405h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverResourceManager:
    mov dword [currentHash], 04D905F0Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRecoverTransactionManager:
    mov dword [currentHash], 082B5B60Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterProtocolAddressInformation:
    mov dword [currentHash], 0D54EF51Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRegisterThreadTerminatePort:
    mov dword [currentHash], 066F67F62h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseKeyedEvent:
    mov dword [currentHash], 008890F12h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseWorkerFactoryWorker:
    mov dword [currentHash], 0BC8D8A29h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveIoCompletionEx:
    mov dword [currentHash], 0B49732A8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRemoveProcessDebug:
    mov dword [currentHash], 01050FE46h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameKey:
    mov dword [currentHash], 01B0C46D8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRenameTransactionManager:
    mov dword [currentHash], 02FA9E7F0h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplaceKey:
    mov dword [currentHash], 066CE7554h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplacePartitionUnit:
    mov dword [currentHash], 022BE3E1Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReplyWaitReplyPort:
    mov dword [currentHash], 024B42B2Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestPort:
    mov dword [currentHash], 0A0374F24h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetEvent:
    mov dword [currentHash], 044CE8F88h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResetWriteWatch:
    mov dword [currentHash], 0FCE9375Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRestoreKey:
    mov dword [currentHash], 0FB3EE7A5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtResumeProcess:
    mov dword [currentHash], 011A90C20h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRevertContainerImpersonation:
    mov dword [currentHash], 0C629C4C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackComplete:
    mov dword [currentHash], 059204DCCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackEnlistment:
    mov dword [currentHash], 031872C15h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackRegistryTransaction:
    mov dword [currentHash], 0CA51CAC3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackTransaction:
    mov dword [currentHash], 09CBDDA69h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollforwardTransactionManager:
    mov dword [currentHash], 003AF9F82h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKey:
    mov dword [currentHash], 03BAF2A30h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveKeyEx:
    mov dword [currentHash], 09798D324h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSaveMergedKeys:
    mov dword [currentHash], 067827A6Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSecureConnectPort:
    mov dword [currentHash], 0983281BCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSerializeBoot:
    mov dword [currentHash], 0CBD8D946h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootEntryOrder:
    mov dword [currentHash], 0960E8E84h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetBootOptions:
    mov dword [currentHash], 0779C2F4Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel:
    mov dword [currentHash], 0AABA3194h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetCachedSigningLevel2:
    mov dword [currentHash], 03E10D901h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetContextThread:
    mov dword [currentHash], 0AB9BA70Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDebugFilterState:
    mov dword [currentHash], 0B3316903h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultHardErrorPort:
    mov dword [currentHash], 0A734A0BFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultLocale:
    mov dword [currentHash], 0452D7FEBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDefaultUILanguage:
    mov dword [currentHash], 0299B6E3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetDriverEntryOrder:
    mov dword [currentHash], 013A51131h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetEaFile:
    mov dword [currentHash], 0C0FA48C8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighEventPair:
    mov dword [currentHash], 0D753F5CCh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetHighWaitLowEventPair:
    mov dword [currentHash], 03F6ECE0Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIRTimer:
    mov dword [currentHash], 00850DB12h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationDebugObject:
    mov dword [currentHash], 08837B8BBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationEnlistment:
    mov dword [currentHash], 0479B3A4Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationJobObject:
    mov dword [currentHash], 08ED07ACFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationKey:
    mov dword [currentHash], 0C2785060h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationResourceManager:
    mov dword [currentHash], 0C41FD0BDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationSymbolicLink:
    mov dword [currentHash], 0A8A67607h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationToken:
    mov dword [currentHash], 063D6755Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransaction:
    mov dword [currentHash], 01681381Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationTransactionManager:
    mov dword [currentHash], 005349715h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationVirtualMemory:
    mov dword [currentHash], 09B028F9Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationWorkerFactory:
    mov dword [currentHash], 0786D108Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIntervalProfile:
    mov dword [currentHash], 076A1B0F8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletion:
    mov dword [currentHash], 002D843F7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetIoCompletionEx:
    mov dword [currentHash], 0C92F0C73h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLdtEntries:
    mov dword [currentHash], 05B6A2499h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowEventPair:
    mov dword [currentHash], 040D27C5Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetLowWaitHighEventPair:
    mov dword [currentHash], 0A43DA4A3h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetQuotaInformationFile:
    mov dword [currentHash], 0A23B5420h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSecurityObject:
    mov dword [currentHash], 0FAD676B9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValue:
    mov dword [currentHash], 01C9F0B0Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemEnvironmentValueEx:
    mov dword [currentHash], 00F935D4Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemInformation:
    mov dword [currentHash], 0072F4385h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemPowerState:
    mov dword [currentHash], 010892602h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetSystemTime:
    mov dword [currentHash], 03EAD353Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetThreadExecutionState:
    mov dword [currentHash], 012B3ECA8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimer2:
    mov dword [currentHash], 0CF356FABh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerEx:
    mov dword [currentHash], 01CFA2E40h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetTimerResolution:
    mov dword [currentHash], 054CE745Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetUuidSeed:
    mov dword [currentHash], 01DCF5F12h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetVolumeInformationFile:
    mov dword [currentHash], 03402BB21h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetWnfProcessNotificationEvent:
    mov dword [currentHash], 016CB77DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownSystem:
    mov dword [currentHash], 0C0ECECB7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtShutdownWorkerFactory:
    mov dword [currentHash], 0189320D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSignalAndWaitForSingleObject:
    mov dword [currentHash], 029111FA8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSinglePhaseReject:
    mov dword [currentHash], 0249E3611h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartProfile:
    mov dword [currentHash], 060356B93h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStopProfile:
    mov dword [currentHash], 0E5B21DE6h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSubscribeWnfStateChange:
    mov dword [currentHash], 006A77F3Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendProcess:
    mov dword [currentHash], 077AB5232h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSuspendThread:
    mov dword [currentHash], 01CBD5E1Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSystemDebugControl:
    mov dword [currentHash], 0BDAC5CBAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateEnclave:
    mov dword [currentHash], 0613E59E2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTerminateJobObject:
    mov dword [currentHash], 01EA037FDh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTestAlert:
    mov dword [currentHash], 08CAFE33Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawRegistry:
    mov dword [currentHash], 03EAC3439h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtThawTransactions:
    mov dword [currentHash], 0900AF0DEh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTraceControl:
    mov dword [currentHash], 0B865DEF4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtTranslateFilePath:
    mov dword [currentHash], 0F2B2CFE7h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUmsThreadYield:
    mov dword [currentHash], 009B78290h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadDriver:
    mov dword [currentHash], 09CD7A65Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey:
    mov dword [currentHash], 05B2C58B5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKey2:
    mov dword [currentHash], 0EE7706E9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnloadKeyEx:
    mov dword [currentHash], 03F99C3E2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockFile:
    mov dword [currentHash], 0E1781BFFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnlockVirtualMemory:
    mov dword [currentHash], 00F98213Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnmapViewOfSectionEx:
    mov dword [currentHash], 040DA1604h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUnsubscribeWnfStateChange:
    mov dword [currentHash], 0209C6524h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtUpdateWnfStateData:
    mov dword [currentHash], 00C851638h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtVdmControl:
    mov dword [currentHash], 01BC3E185h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForAlertByThreadId:
    mov dword [currentHash], 06CABA912h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForDebugEvent:
    mov dword [currentHash], 0968A759Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForKeyedEvent:
    mov dword [currentHash], 0F918FC89h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWorkViaWorkerFactory:
    mov dword [currentHash], 0489E7A52h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitHighEventPair:
    mov dword [currentHash], 023332BA4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitLowEventPair:
    mov dword [currentHash], 072DF924Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAcquireCMFViewOwnership:
    mov dword [currentHash], 00B4D01D4h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCancelDeviceWakeupRequest:
    mov dword [currentHash], 0D421DCA5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearAllSavepointsTransaction:
    mov dword [currentHash], 09E05BE8Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClearSavepointTransaction:
    mov dword [currentHash], 0FD69C1A2h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRollbackSavepointTransaction:
    mov dword [currentHash], 01C47DE17h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointTransaction:
    mov dword [currentHash], 01C844249h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSavepointComplete:
    mov dword [currentHash], 01A90361Ah    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateSectionEx:
    mov dword [currentHash], 0984DC69Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateCrossVmEvent:
    mov dword [currentHash], 0C951D0DFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtGetPlugPlayEvent:
    mov dword [currentHash], 0E0452617h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtListTransactions:
    mov dword [currentHash], 0ECB6E62Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtMarshallTransaction:
    mov dword [currentHash], 07ADD647Dh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtPullTransaction:
    mov dword [currentHash], 07D557FF9h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtReleaseCMFViewOwnership:
    mov dword [currentHash], 05A6F42F8h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWaitForWnfNotifications:
    mov dword [currentHash], 00D992ACBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtStartTm:
    mov dword [currentHash], 0C38E50AFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtSetInformationProcess:
    mov dword [currentHash], 06DAF4A7Ch    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestDeviceWakeup:
    mov dword [currentHash], 05517B042h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtRequestWakeupLatency:
    mov dword [currentHash], 0043EE142h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtQuerySystemTime:
    mov dword [currentHash], 0EAAEF31Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtManageHotPatch:
    mov dword [currentHash], 0F0D1E66Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtContinueEx:
    mov dword [currentHash], 02794F0CBh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

RtlCreateUserThread:
    mov dword [currentHash], 016AE441Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

