.intel_syntax noprefix
.data
currentHash:    .long   0
returnAddress:  .quad   0
syscallNumber:  .long   0
syscallAddress: .quad   0

.text
.global NtAllocateVirtualMemory
.global NtWriteVirtualMemory
.global NtProtectVirtualMemory
.global NtCreateThreadEx

.global WhisperMain
.extern SW2_GetSyscallNumber
.extern SW2_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                           # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber + RIP], eax    # Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress            # Get a random syscall address
    mov qword ptr [syscallAddress + RIP], rax   # Save the random syscall address
    xor rax, rax
    mov eax, dword ptr [syscallNumber + RIP]    # Restore the syscall vallue
    add rsp, 0x28
    mov rcx, [rsp+ 8]                           # Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword ptr [returnAddress + RIP]         # Save the original return address
    call qword ptr [syscallAddress + RIP]       # Issue syscall
    push qword ptr [returnAddress + RIP]        # Restore the original return address
    ret

NtAccessCheck:
    mov dword ptr [currentHash + RIP], 0x0A9019EDB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWorkerFactoryWorkerReady:
    mov dword ptr [currentHash + RIP], 0x0279B1D25   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcceptConnectPort:
    mov dword ptr [currentHash + RIP], 0x0A63D2532   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPagesScatter:
    mov dword ptr [currentHash + RIP], 0x01BA32709   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x09AA0BAFC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallbackReturn:
    mov dword ptr [currentHash + RIP], 0x0068C251C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFile:
    mov dword ptr [currentHash + RIP], 0x04098542E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeviceIoControlFile:
    mov dword ptr [currentHash + RIP], 0x064F2B7C6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFile:
    mov dword ptr [currentHash + RIP], 0x0F1DBDB5D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletion:
    mov dword ptr [currentHash + RIP], 0x04EA84E3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseSemaphore:
    mov dword ptr [currentHash + RIP], 0x076E47870   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePort:
    mov dword ptr [currentHash + RIP], 0x06AF2899C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyPort:
    mov dword ptr [currentHash + RIP], 0x020B11F12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationThread:
    mov dword ptr [currentHash + RIP], 0x0F65ABCF3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEvent:
    mov dword ptr [currentHash + RIP], 0x00E910704   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClose:
    mov dword ptr [currentHash + RIP], 0x0DC482529   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryObject:
    mov dword ptr [currentHash + RIP], 0x0043FDD12   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationFile:
    mov dword ptr [currentHash + RIP], 0x03EDFC498   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKey:
    mov dword ptr [currentHash + RIP], 0x0249C4949   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateValueKey:
    mov dword ptr [currentHash + RIP], 0x0271BC085   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFindAtom:
    mov dword ptr [currentHash + RIP], 0x0DF41D0DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultLocale:
    mov dword ptr [currentHash + RIP], 0x0D138E3EF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryKey:
    mov dword ptr [currentHash + RIP], 0x00B173288   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryValueKey:
    mov dword ptr [currentHash + RIP], 0x0221CD262   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00F8D111B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationProcess:
    mov dword ptr [currentHash + RIP], 0x0802C8FB1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects32:
    mov dword ptr [currentHash + RIP], 0x0408E5C41   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteFileGather:
    mov dword ptr [currentHash + RIP], 0x0BB3FEDFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKey:
    mov dword ptr [currentHash + RIP], 0x08D1F6008   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x003997D1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateClientOfPort:
    mov dword ptr [currentHash + RIP], 0x0E570FAFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseMutant:
    mov dword ptr [currentHash + RIP], 0x020A46D7C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationToken:
    mov dword ptr [currentHash + RIP], 0x08792109A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWaitReplyPort:
    mov dword ptr [currentHash + RIP], 0x0D37FD6F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x043916F45   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadToken:
    mov dword ptr [currentHash + RIP], 0x0015B9873   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationThread:
    mov dword ptr [currentHash + RIP], 0x0705F2C9E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcess:
    mov dword ptr [currentHash + RIP], 0x0D554CCD8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationFile:
    mov dword ptr [currentHash + RIP], 0x09C38540E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSection:
    mov dword ptr [currentHash + RIP], 0x00E962FC5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x076B1B6EE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSection:
    mov dword ptr [currentHash + RIP], 0x012813051   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReceivePortEx:
    mov dword ptr [currentHash + RIP], 0x06D6F33BA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateProcess:
    mov dword ptr [currentHash + RIP], 0x0EFAF0A3F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEventBoostPriority:
    mov dword ptr [currentHash + RIP], 0x018A10E0E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadFileScatter:
    mov dword ptr [currentHash + RIP], 0x05BD20D17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThreadTokenEx:
    mov dword ptr [currentHash + RIP], 0x01B285B10   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessTokenEx:
    mov dword ptr [currentHash + RIP], 0x0B0A9F414   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPerformanceCounter:
    mov dword ptr [currentHash + RIP], 0x051F84F55   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateKey:
    mov dword ptr [currentHash + RIP], 0x009AF4870   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenFile:
    mov dword ptr [currentHash + RIP], 0x02A846226   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDelayExecution:
    mov dword ptr [currentHash + RIP], 0x04EC24853   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFile:
    mov dword ptr [currentHash + RIP], 0x03F9EFEB8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformation:
    mov dword ptr [currentHash + RIP], 0x00D930D01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSection:
    mov dword ptr [currentHash + RIP], 0x01853EA17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimer:
    mov dword ptr [currentHash + RIP], 0x0BD978D3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFsControlFile:
    mov dword ptr [currentHash + RIP], 0x064F5222E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x00F9918F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCloseObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x01A95928A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateObject:
    mov dword ptr [currentHash + RIP], 0x0E45F2C03   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAttributesFile:
    mov dword ptr [currentHash + RIP], 0x0615895C9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearEvent:
    mov dword ptr [currentHash + RIP], 0x06ECF6752   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x009BD1F23   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEvent:
    mov dword ptr [currentHash + RIP], 0x008821906   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustPrivilegesToken:
    mov dword ptr [currentHash + RIP], 0x03DA3650A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDuplicateToken:
    mov dword ptr [currentHash + RIP], 0x07B10817C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinue:
    mov dword ptr [currentHash + RIP], 0x0DEB435C7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDefaultUILanguage:
    mov dword ptr [currentHash + RIP], 0x0F5D7FA65   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThread:
    mov dword ptr [currentHash + RIP], 0x014CF7017   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtYieldExecution:
    mov dword ptr [currentHash + RIP], 0x00397CDCA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtom:
    mov dword ptr [currentHash + RIP], 0x01DB03E29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEvent:
    mov dword ptr [currentHash + RIP], 0x051034E68   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryVolumeInformationFile:
    mov dword ptr [currentHash + RIP], 0x0ED742BD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSection:
    mov dword ptr [currentHash + RIP], 0x0BC9BE029   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFile:
    mov dword ptr [currentHash + RIP], 0x070FA7E52   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtApphelpCacheControl:
    mov dword ptr [currentHash + RIP], 0x049A1B3E7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcessEx:
    mov dword ptr [currentHash + RIP], 0x09210A0AA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThread:
    mov dword ptr [currentHash + RIP], 0x026BC2015   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsProcessInJob:
    mov dword ptr [currentHash + RIP], 0x0E5979949   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtProtectVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0BB18B18B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySection:
    mov dword ptr [currentHash + RIP], 0x09C35BEA5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeThread:
    mov dword ptr [currentHash + RIP], 0x032927E31   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateThread:
    mov dword ptr [currentHash + RIP], 0x00C179F28   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadRequestData:
    mov dword ptr [currentHash + RIP], 0x0B805B2AE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateFile:
    mov dword ptr [currentHash + RIP], 0x09E9CAC04   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEvent:
    mov dword ptr [currentHash + RIP], 0x0F8EB1CFC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWriteRequestData:
    mov dword ptr [currentHash + RIP], 0x0CECA5FFB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x02B38D976   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x08F30935F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForMultipleObjects:
    mov dword ptr [currentHash + RIP], 0x0119D2D13   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationObject:
    mov dword ptr [currentHash + RIP], 0x088151919   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFile:
    mov dword ptr [currentHash + RIP], 0x0A4EAB262   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceEvent:
    mov dword ptr [currentHash + RIP], 0x00EAC1F08   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPowerInformation:
    mov dword ptr [currentHash + RIP], 0x066B04663   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetValueKey:
    mov dword ptr [currentHash + RIP], 0x08ACE4995   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer:
    mov dword ptr [currentHash + RIP], 0x0B5A0C75D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer:
    mov dword ptr [currentHash + RIP], 0x00394393C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByType:
    mov dword ptr [currentHash + RIP], 0x052FFBBAA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultList:
    mov dword ptr [currentHash + RIP], 0x056F9586A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x03EA31E2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    mov dword ptr [currentHash + RIP], 0x018340882   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireProcessActivityReference:
    mov dword ptr [currentHash + RIP], 0x0EF5AE9E7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddAtomEx:
    mov dword ptr [currentHash + RIP], 0x0A59AF542   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddBootEntry:
    mov dword ptr [currentHash + RIP], 0x0A174B5D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAddDriverEntry:
    mov dword ptr [currentHash + RIP], 0x01984096C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustGroupsToken:
    mov dword ptr [currentHash + RIP], 0x0A041F6E5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAdjustTokenClaimsAndDeviceGroups:
    mov dword ptr [currentHash + RIP], 0x039E51CB5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertResumeThread:
    mov dword ptr [currentHash + RIP], 0x0CE9B043D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThread:
    mov dword ptr [currentHash + RIP], 0x07C47E779   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlertThreadByThreadId:
    mov dword ptr [currentHash + RIP], 0x0B32F1E2F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateLocallyUniqueId:
    mov dword ptr [currentHash + RIP], 0x03DCE1F48   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateReserveObject:
    mov dword ptr [currentHash + RIP], 0x07A5A04B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x07BE31438   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateUuids:
    mov dword ptr [currentHash + RIP], 0x01A8B1A17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAllocateVirtualMemoryEx:
    mov dword ptr [currentHash + RIP], 0x0A089F253   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcAcceptConnectPort:
    mov dword ptr [currentHash + RIP], 0x0E0B31EC1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCancelMessage:
    mov dword ptr [currentHash + RIP], 0x0BA95AB2F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPort:
    mov dword ptr [currentHash + RIP], 0x062CE7F66   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcConnectPortEx:
    mov dword ptr [currentHash + RIP], 0x0A7A86A9C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePort:
    mov dword ptr [currentHash + RIP], 0x024BEC0D1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreatePortSection:
    mov dword ptr [currentHash + RIP], 0x0B2AC56F7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateResourceReserve:
    mov dword ptr [currentHash + RIP], 0x07AC96C79   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSectionView:
    mov dword ptr [currentHash + RIP], 0x08A0CB78B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcCreateSecurityContext:
    mov dword ptr [currentHash + RIP], 0x0B690DB09   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeletePortSection:
    mov dword ptr [currentHash + RIP], 0x0F2E819B0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteResourceReserve:
    mov dword ptr [currentHash + RIP], 0x02ADB045B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSectionView:
    mov dword ptr [currentHash + RIP], 0x0F7D1CC5A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDeleteSecurityContext:
    mov dword ptr [currentHash + RIP], 0x00EB20922   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcDisconnectPort:
    mov dword ptr [currentHash + RIP], 0x0A832B99C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientContainerOfPort:
    mov dword ptr [currentHash + RIP], 0x0E47FFFF0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcImpersonateClientOfPort:
    mov dword ptr [currentHash + RIP], 0x05CF17968   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderProcess:
    mov dword ptr [currentHash + RIP], 0x0D5B5DA29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcOpenSenderThread:
    mov dword ptr [currentHash + RIP], 0x08C205696   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformation:
    mov dword ptr [currentHash + RIP], 0x0BAABDCBF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcQueryInformationMessage:
    mov dword ptr [currentHash + RIP], 0x013CCD0F0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcRevokeSecurityContext:
    mov dword ptr [currentHash + RIP], 0x00E5405DC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSendWaitReceivePort:
    mov dword ptr [currentHash + RIP], 0x06CF789E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAlpcSetInformation:
    mov dword ptr [currentHash + RIP], 0x0008E2FD3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAreMappedFilesTheSame:
    mov dword ptr [currentHash + RIP], 0x0D74AEEEE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssignProcessToJobObject:
    mov dword ptr [currentHash + RIP], 0x00C31852C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAssociateWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x00833388E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCallEnclave:
    mov dword ptr [currentHash + RIP], 0x01A961A3C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelIoFileEx:
    mov dword ptr [currentHash + RIP], 0x09089DC52   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelSynchronousIoFile:
    mov dword ptr [currentHash + RIP], 0x0F6C68015   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelTimer2:
    mov dword ptr [currentHash + RIP], 0x0E81515BA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x0881D8E8F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitComplete:
    mov dword ptr [currentHash + RIP], 0x038AC002E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitEnlistment:
    mov dword ptr [currentHash + RIP], 0x0C226DBA2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x0BAB5B825   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCommitTransaction:
    mov dword ptr [currentHash + RIP], 0x008802FD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompactKeys:
    mov dword ptr [currentHash + RIP], 0x0218E320A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareObjects:
    mov dword ptr [currentHash + RIP], 0x043D94753   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareSigningLevels:
    mov dword ptr [currentHash + RIP], 0x040920046   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompareTokens:
    mov dword ptr [currentHash + RIP], 0x055DD3B01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompleteConnectPort:
    mov dword ptr [currentHash + RIP], 0x02172C21D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCompressKey:
    mov dword ptr [currentHash + RIP], 0x01494070F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConnectPort:
    mov dword ptr [currentHash + RIP], 0x03CB1253C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    mov dword ptr [currentHash + RIP], 0x00BAA2533   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDebugObject:
    mov dword ptr [currentHash + RIP], 0x002BCEAC0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x01AA5E4D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateDirectoryObjectEx:
    mov dword ptr [currentHash + RIP], 0x07C7C820A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnclave:
    mov dword ptr [currentHash + RIP], 0x0C691F25A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEnlistment:
    mov dword ptr [currentHash + RIP], 0x03FD91D8F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateEventPair:
    mov dword ptr [currentHash + RIP], 0x010B64E7F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIRTimer:
    mov dword ptr [currentHash + RIP], 0x03D851B32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateIoCompletion:
    mov dword ptr [currentHash + RIP], 0x0030C65D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobObject:
    mov dword ptr [currentHash + RIP], 0x08CA1E65E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateJobSet:
    mov dword ptr [currentHash + RIP], 0x082031A2F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyTransacted:
    mov dword ptr [currentHash + RIP], 0x0168A9797   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x0FE40BF96   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateLowBoxToken:
    mov dword ptr [currentHash + RIP], 0x0C3A1CD3E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMailslotFile:
    mov dword ptr [currentHash + RIP], 0x0A7B12F95   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateMutant:
    mov dword ptr [currentHash + RIP], 0x0D34E2848   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateNamedPipeFile:
    mov dword ptr [currentHash + RIP], 0x068F88CA2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePagingFile:
    mov dword ptr [currentHash + RIP], 0x0D17C3A7D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePartition:
    mov dword ptr [currentHash + RIP], 0x08D2CE5F6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePort:
    mov dword ptr [currentHash + RIP], 0x0A276A3FA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreatePrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x08C2F4972   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProcess:
    mov dword ptr [currentHash + RIP], 0x03F9D2DF2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfile:
    mov dword ptr [currentHash + RIP], 0x004847E04   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateProfileEx:
    mov dword ptr [currentHash + RIP], 0x07A804447   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x084ABC67A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateResourceManager:
    mov dword ptr [currentHash + RIP], 0x078228069   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSemaphore:
    mov dword ptr [currentHash + RIP], 0x078A6B50E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x008199015   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateThreadEx:
    mov dword ptr [currentHash + RIP], 0x014AB4C6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer:
    mov dword ptr [currentHash + RIP], 0x073D6416A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTimer2:
    mov dword ptr [currentHash + RIP], 0x019A559AB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateToken:
    mov dword ptr [currentHash + RIP], 0x067C0594C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTokenEx:
    mov dword ptr [currentHash + RIP], 0x086830DB1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransaction:
    mov dword ptr [currentHash + RIP], 0x0D099D60D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateTransactionManager:
    mov dword ptr [currentHash + RIP], 0x005222F9E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateUserProcess:
    mov dword ptr [currentHash + RIP], 0x0953FAE90   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitCompletionPacket:
    mov dword ptr [currentHash + RIP], 0x0F7C28B29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWaitablePort:
    mov dword ptr [currentHash + RIP], 0x066B24F6E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWnfStateName:
    mov dword ptr [currentHash + RIP], 0x0F4B2FD20   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x004951C72   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugActiveProcess:
    mov dword ptr [currentHash + RIP], 0x0E03DD9B1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDebugContinue:
    mov dword ptr [currentHash + RIP], 0x0769689CE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteAtom:
    mov dword ptr [currentHash + RIP], 0x0E27EE5EC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteBootEntry:
    mov dword ptr [currentHash + RIP], 0x0018D35C0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteDriverEntry:
    mov dword ptr [currentHash + RIP], 0x00F827B0E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteFile:
    mov dword ptr [currentHash + RIP], 0x0E245E0DC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteKey:
    mov dword ptr [currentHash + RIP], 0x09F2B8EB0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x098DEA590   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeletePrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x03E90470D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteValueKey:
    mov dword ptr [currentHash + RIP], 0x006FB3741   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateData:
    mov dword ptr [currentHash + RIP], 0x0C3793369   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDeleteWnfStateName:
    mov dword ptr [currentHash + RIP], 0x0ED431050   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisableLastKnownGood:
    mov dword ptr [currentHash + RIP], 0x0E9C0F37E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDisplayString:
    mov dword ptr [currentHash + RIP], 0x07ECE6A5E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtDrawText:
    mov dword ptr [currentHash + RIP], 0x0E0BAEB2D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnableLastKnownGood:
    mov dword ptr [currentHash + RIP], 0x0B029493F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateBootEntries:
    mov dword ptr [currentHash + RIP], 0x02D911828   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateDriverEntries:
    mov dword ptr [currentHash + RIP], 0x0E153F3CC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateSystemEnvironmentValuesEx:
    mov dword ptr [currentHash + RIP], 0x043531F97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtEnumerateTransactionObject:
    mov dword ptr [currentHash + RIP], 0x0CEE626CD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtExtendSection:
    mov dword ptr [currentHash + RIP], 0x09F90DB3A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterBootOption:
    mov dword ptr [currentHash + RIP], 0x0048E3803   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterToken:
    mov dword ptr [currentHash + RIP], 0x007921D1A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFilterTokenEx:
    mov dword ptr [currentHash + RIP], 0x00C875654   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushBuffersFileEx:
    mov dword ptr [currentHash + RIP], 0x00AA9CC97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstallUILanguage:
    mov dword ptr [currentHash + RIP], 0x01FBBD112   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushInstructionCache:
    mov dword ptr [currentHash + RIP], 0x01526D977   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushKey:
    mov dword ptr [currentHash + RIP], 0x02D9F0A32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushProcessWriteBuffers:
    mov dword ptr [currentHash + RIP], 0x0E8B9EE28   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x009A2794B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFlushWriteBuffer:
    mov dword ptr [currentHash + RIP], 0x06DB47D2B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreeUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x012B3FAA8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeRegistry:
    mov dword ptr [currentHash + RIP], 0x0028F15E3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtFreezeTransactions:
    mov dword ptr [currentHash + RIP], 0x0811EB399   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCachedSigningLevel:
    mov dword ptr [currentHash + RIP], 0x064F8ABA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCompleteWnfStateSubscription:
    mov dword ptr [currentHash + RIP], 0x046CE265B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetContextThread:
    mov dword ptr [currentHash + RIP], 0x01CF8EEE9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumber:
    mov dword ptr [currentHash + RIP], 0x00CA2F4E8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetCurrentProcessorNumberEx:
    mov dword ptr [currentHash + RIP], 0x0DC4B2131   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetDevicePowerState:
    mov dword ptr [currentHash + RIP], 0x03090393C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetMUIRegistryInfo:
    mov dword ptr [currentHash + RIP], 0x01DA1010A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextProcess:
    mov dword ptr [currentHash + RIP], 0x0C12FC2B0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNextThread:
    mov dword ptr [currentHash + RIP], 0x0399EF43F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNlsSectionPtr:
    mov dword ptr [currentHash + RIP], 0x07AD39C47   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetNotificationResourceManager:
    mov dword ptr [currentHash + RIP], 0x01F884540   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetWriteWatch:
    mov dword ptr [currentHash + RIP], 0x09059EACA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateAnonymousToken:
    mov dword ptr [currentHash + RIP], 0x01F810F3C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtImpersonateThread:
    mov dword ptr [currentHash + RIP], 0x026872421   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeEnclave:
    mov dword ptr [currentHash + RIP], 0x0D48B0A2E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeNlsFiles:
    mov dword ptr [currentHash + RIP], 0x09C00BB9A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitializeRegistry:
    mov dword ptr [currentHash + RIP], 0x0DCCD25BC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtInitiatePowerAction:
    mov dword ptr [currentHash + RIP], 0x0100CF11F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsSystemResumeAutomatic:
    mov dword ptr [currentHash + RIP], 0x082891F8A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtIsUILanguageComitted:
    mov dword ptr [currentHash + RIP], 0x0839EC332   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListenPort:
    mov dword ptr [currentHash + RIP], 0x06171987F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadDriver:
    mov dword ptr [currentHash + RIP], 0x0BEA4C9A5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadEnclaveData:
    mov dword ptr [currentHash + RIP], 0x042999034   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadHotPatch:
    mov dword ptr [currentHash + RIP], 0x090CD6BA9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey:
    mov dword ptr [currentHash + RIP], 0x0407CC165   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKey2:
    mov dword ptr [currentHash + RIP], 0x0253C6F20   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLoadKeyEx:
    mov dword ptr [currentHash + RIP], 0x00B19CF44   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockFile:
    mov dword ptr [currentHash + RIP], 0x078F0547A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockProductActivationKeys:
    mov dword ptr [currentHash + RIP], 0x032D62CB5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockRegistryKey:
    mov dword ptr [currentHash + RIP], 0x01F27FA45   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtLockVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0CD5FC9D3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakePermanentObject:
    mov dword ptr [currentHash + RIP], 0x0A4BAAE24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMakeTemporaryObject:
    mov dword ptr [currentHash + RIP], 0x0849C9E11   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManagePartition:
    mov dword ptr [currentHash + RIP], 0x03CB1DE21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapCMFModule:
    mov dword ptr [currentHash + RIP], 0x04CEE1854   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapUserPhysicalPages:
    mov dword ptr [currentHash + RIP], 0x049CF5E48   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMapViewOfSectionEx:
    mov dword ptr [currentHash + RIP], 0x0B952E586   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyBootEntry:
    mov dword ptr [currentHash + RIP], 0x03D9B1738   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtModifyDriverEntry:
    mov dword ptr [currentHash + RIP], 0x00B961D18   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFile:
    mov dword ptr [currentHash + RIP], 0x0CD7BBBE1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeDirectoryFileEx:
    mov dword ptr [currentHash + RIP], 0x0689A244F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeKey:
    mov dword ptr [currentHash + RIP], 0x00AD3E8A8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeMultipleKeys:
    mov dword ptr [currentHash + RIP], 0x0DFCEA82C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtNotifyChangeSession:
    mov dword ptr [currentHash + RIP], 0x067CD4B4E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEnlistment:
    mov dword ptr [currentHash + RIP], 0x009A70C3D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenEventPair:
    mov dword ptr [currentHash + RIP], 0x05017B441   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenIoCompletion:
    mov dword ptr [currentHash + RIP], 0x021544259   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenJobObject:
    mov dword ptr [currentHash + RIP], 0x0C29CEC21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyEx:
    mov dword ptr [currentHash + RIP], 0x073D4BF60   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransacted:
    mov dword ptr [currentHash + RIP], 0x0130E9110   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyTransactedEx:
    mov dword ptr [currentHash + RIP], 0x01C1E50DA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x03AB15D6A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenMutant:
    mov dword ptr [currentHash + RIP], 0x03CB610E6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x06EAF6E02   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPartition:
    mov dword ptr [currentHash + RIP], 0x078E04669   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenPrivateNamespace:
    mov dword ptr [currentHash + RIP], 0x0AE126BB0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenProcessToken:
    mov dword ptr [currentHash + RIP], 0x0390D01A4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x0CE85EA5F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenResourceManager:
    mov dword ptr [currentHash + RIP], 0x015BDE3BD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSemaphore:
    mov dword ptr [currentHash + RIP], 0x03EB437D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSession:
    mov dword ptr [currentHash + RIP], 0x0F56EF5F8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenSymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x0A63B9E97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenThread:
    mov dword ptr [currentHash + RIP], 0x0EEC9E46F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTimer:
    mov dword ptr [currentHash + RIP], 0x00FCF7540   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransaction:
    mov dword ptr [currentHash + RIP], 0x0CEC5EA57   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtOpenTransactionManager:
    mov dword ptr [currentHash + RIP], 0x0C415D4B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPlugPlayControl:
    mov dword ptr [currentHash + RIP], 0x0B16DD7FF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareComplete:
    mov dword ptr [currentHash + RIP], 0x038A1DEAA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrePrepareEnlistment:
    mov dword ptr [currentHash + RIP], 0x00BA4CCFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareComplete:
    mov dword ptr [currentHash + RIP], 0x01884040A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrepareEnlistment:
    mov dword ptr [currentHash + RIP], 0x0086715F5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeCheck:
    mov dword ptr [currentHash + RIP], 0x03497252B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegeObjectAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x01E5000FC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPrivilegedServiceAuditAlarm:
    mov dword ptr [currentHash + RIP], 0x01F91F00D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationComplete:
    mov dword ptr [currentHash + RIP], 0x02F57C91A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPropagationFailed:
    mov dword ptr [currentHash + RIP], 0x08C9AF84A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPulseEvent:
    mov dword ptr [currentHash + RIP], 0x082BF8928   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryAuxiliaryCounterFrequency:
    mov dword ptr [currentHash + RIP], 0x0A81B85BE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0DD40F219   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryBootOptions:
    mov dword ptr [currentHash + RIP], 0x07A15AA30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDebugFilterState:
    mov dword ptr [currentHash + RIP], 0x016B43DF8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryFileEx:
    mov dword ptr [currentHash + RIP], 0x0C5597C59   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDirectoryObject:
    mov dword ptr [currentHash + RIP], 0x0E73AEDA4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryDriverEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0AB9A9331   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryEaFile:
    mov dword ptr [currentHash + RIP], 0x01E3E991D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryFullAttributesFile:
    mov dword ptr [currentHash + RIP], 0x09CC89062   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationAtom:
    mov dword ptr [currentHash + RIP], 0x0FE692358   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationByName:
    mov dword ptr [currentHash + RIP], 0x0A61EB9A5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationEnlistment:
    mov dword ptr [currentHash + RIP], 0x0861B979E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationJobObject:
    mov dword ptr [currentHash + RIP], 0x014BF0E31   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationPort:
    mov dword ptr [currentHash + RIP], 0x01AB53D1E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationResourceManager:
    mov dword ptr [currentHash + RIP], 0x00B331392   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransaction:
    mov dword ptr [currentHash + RIP], 0x0E14D0A1B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationTransactionManager:
    mov dword ptr [currentHash + RIP], 0x086259A8F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInformationWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x0FE6EECE2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryInstallUILanguage:
    mov dword ptr [currentHash + RIP], 0x0EC0EED97   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIntervalProfile:
    mov dword ptr [currentHash + RIP], 0x0EE59C6CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryIoCompletion:
    mov dword ptr [currentHash + RIP], 0x09E07A285   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryLicenseValue:
    mov dword ptr [currentHash + RIP], 0x03CA4E8EA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMultipleValueKey:
    mov dword ptr [currentHash + RIP], 0x031982403   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryMutant:
    mov dword ptr [currentHash + RIP], 0x0004F01C5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeys:
    mov dword ptr [currentHash + RIP], 0x045DD4A42   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryOpenSubKeysEx:
    mov dword ptr [currentHash + RIP], 0x0399CF9E4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryPortInformationProcess:
    mov dword ptr [currentHash + RIP], 0x01C025DDE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryQuotaInformationFile:
    mov dword ptr [currentHash + RIP], 0x06D3D3189   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityAttributesToken:
    mov dword ptr [currentHash + RIP], 0x0E2462E1D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityObject:
    mov dword ptr [currentHash + RIP], 0x02A3454A9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySecurityPolicy:
    mov dword ptr [currentHash + RIP], 0x0ECDAD36D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySemaphore:
    mov dword ptr [currentHash + RIP], 0x0F4181594   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySymbolicLinkObject:
    mov dword ptr [currentHash + RIP], 0x0869E8C00   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValue:
    mov dword ptr [currentHash + RIP], 0x014A2E2B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemEnvironmentValueEx:
    mov dword ptr [currentHash + RIP], 0x0F811056B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemInformationEx:
    mov dword ptr [currentHash + RIP], 0x0F69123CF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryTimerResolution:
    mov dword ptr [currentHash + RIP], 0x00C9A0C0D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateData:
    mov dword ptr [currentHash + RIP], 0x0A707AC6D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueryWnfStateNameInformation:
    mov dword ptr [currentHash + RIP], 0x00E907213   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQueueApcThreadEx:
    mov dword ptr [currentHash + RIP], 0x0C4D91783   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseException:
    mov dword ptr [currentHash + RIP], 0x03AEE15B3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRaiseHardError:
    mov dword ptr [currentHash + RIP], 0x0C24EE0DE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReadOnlyEnlistment:
    mov dword ptr [currentHash + RIP], 0x04C562F41   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverEnlistment:
    mov dword ptr [currentHash + RIP], 0x0AF92DC15   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverResourceManager:
    mov dword ptr [currentHash + RIP], 0x0B267D89B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRecoverTransactionManager:
    mov dword ptr [currentHash + RIP], 0x0098E6716   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterProtocolAddressInformation:
    mov dword ptr [currentHash + RIP], 0x013851510   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRegisterThreadTerminatePort:
    mov dword ptr [currentHash + RIP], 0x036F4733A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x0C04AF9FE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseWorkerFactoryWorker:
    mov dword ptr [currentHash + RIP], 0x069404395   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveIoCompletionEx:
    mov dword ptr [currentHash + RIP], 0x0849743E9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRemoveProcessDebug:
    mov dword ptr [currentHash + RIP], 0x058A1B6F6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameKey:
    mov dword ptr [currentHash + RIP], 0x063FC9FF8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRenameTransactionManager:
    mov dword ptr [currentHash + RIP], 0x02991E0CA   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplaceKey:
    mov dword ptr [currentHash + RIP], 0x0A9E78850   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplacePartitionUnit:
    mov dword ptr [currentHash + RIP], 0x0A834A2B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReplyWaitReplyPort:
    mov dword ptr [currentHash + RIP], 0x0BA38AFB8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestPort:
    mov dword ptr [currentHash + RIP], 0x010B22D1C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetEvent:
    mov dword ptr [currentHash + RIP], 0x068CB6B5C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResetWriteWatch:
    mov dword ptr [currentHash + RIP], 0x00CE1FABE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRestoreKey:
    mov dword ptr [currentHash + RIP], 0x0CBF2AE6D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtResumeProcess:
    mov dword ptr [currentHash + RIP], 0x065DB6654   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRevertContainerImpersonation:
    mov dword ptr [currentHash + RIP], 0x0C649C6DB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackComplete:
    mov dword ptr [currentHash + RIP], 0x058B47036   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackEnlistment:
    mov dword ptr [currentHash + RIP], 0x009A32A34   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackRegistryTransaction:
    mov dword ptr [currentHash + RIP], 0x01853DAFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackTransaction:
    mov dword ptr [currentHash + RIP], 0x0E6CDE257   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollforwardTransactionManager:
    mov dword ptr [currentHash + RIP], 0x00FB2579C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKey:
    mov dword ptr [currentHash + RIP], 0x043957E22   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveKeyEx:
    mov dword ptr [currentHash + RIP], 0x03BB0EFEC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSaveMergedKeys:
    mov dword ptr [currentHash + RIP], 0x061DA644C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSecureConnectPort:
    mov dword ptr [currentHash + RIP], 0x064EE4140   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSerializeBoot:
    mov dword ptr [currentHash + RIP], 0x0ACF829E0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0714E07B7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetBootOptions:
    mov dword ptr [currentHash + RIP], 0x0539F9DC3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel:
    mov dword ptr [currentHash + RIP], 0x0309B7420   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetCachedSigningLevel2:
    mov dword ptr [currentHash + RIP], 0x010ABA14C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetContextThread:
    mov dword ptr [currentHash + RIP], 0x0341FF936   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDebugFilterState:
    mov dword ptr [currentHash + RIP], 0x00CB2781C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultHardErrorPort:
    mov dword ptr [currentHash + RIP], 0x026B23B30   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultLocale:
    mov dword ptr [currentHash + RIP], 0x0353ACB21   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDefaultUILanguage:
    mov dword ptr [currentHash + RIP], 0x015BA1616   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetDriverEntryOrder:
    mov dword ptr [currentHash + RIP], 0x0F248DAEE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetEaFile:
    mov dword ptr [currentHash + RIP], 0x036812637   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighEventPair:
    mov dword ptr [currentHash + RIP], 0x0C29395B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetHighWaitLowEventPair:
    mov dword ptr [currentHash + RIP], 0x04C005881   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIRTimer:
    mov dword ptr [currentHash + RIP], 0x0139F1504   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationDebugObject:
    mov dword ptr [currentHash + RIP], 0x0795A51D9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationEnlistment:
    mov dword ptr [currentHash + RIP], 0x0CD50ECE5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationJobObject:
    mov dword ptr [currentHash + RIP], 0x024B82225   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationKey:
    mov dword ptr [currentHash + RIP], 0x09085B12D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationResourceManager:
    mov dword ptr [currentHash + RIP], 0x0DE47CAE5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationSymbolicLink:
    mov dword ptr [currentHash + RIP], 0x041D54261   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationToken:
    mov dword ptr [currentHash + RIP], 0x02B95753A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransaction:
    mov dword ptr [currentHash + RIP], 0x09813AA9F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationTransactionManager:
    mov dword ptr [currentHash + RIP], 0x07B2363A2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x042535CB7   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x04890306E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIntervalProfile:
    mov dword ptr [currentHash + RIP], 0x082157840   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletion:
    mov dword ptr [currentHash + RIP], 0x04AA27069   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetIoCompletionEx:
    mov dword ptr [currentHash + RIP], 0x030CAC6B4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLdtEntries:
    mov dword ptr [currentHash + RIP], 0x01E87311D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowEventPair:
    mov dword ptr [currentHash + RIP], 0x010B3CCFD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetLowWaitHighEventPair:
    mov dword ptr [currentHash + RIP], 0x062AE067B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetQuotaInformationFile:
    mov dword ptr [currentHash + RIP], 0x081155931   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSecurityObject:
    mov dword ptr [currentHash + RIP], 0x0A698883A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValue:
    mov dword ptr [currentHash + RIP], 0x035265E32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemEnvironmentValueEx:
    mov dword ptr [currentHash + RIP], 0x0EF14186B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemInformation:
    mov dword ptr [currentHash + RIP], 0x08C97D237   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemPowerState:
    mov dword ptr [currentHash + RIP], 0x0F5B40CE8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetSystemTime:
    mov dword ptr [currentHash + RIP], 0x09A8EA717   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetThreadExecutionState:
    mov dword ptr [currentHash + RIP], 0x026DDDD82   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimer2:
    mov dword ptr [currentHash + RIP], 0x03F979F01   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerEx:
    mov dword ptr [currentHash + RIP], 0x040AF6214   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetTimerResolution:
    mov dword ptr [currentHash + RIP], 0x0009A624F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetUuidSeed:
    mov dword ptr [currentHash + RIP], 0x002401EFF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetVolumeInformationFile:
    mov dword ptr [currentHash + RIP], 0x0D647E8D4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetWnfProcessNotificationEvent:
    mov dword ptr [currentHash + RIP], 0x0F06B1976   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownSystem:
    mov dword ptr [currentHash + RIP], 0x004AF2B3C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtShutdownWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x0C096F42B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSignalAndWaitForSingleObject:
    mov dword ptr [currentHash + RIP], 0x0C69CC001   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSinglePhaseReject:
    mov dword ptr [currentHash + RIP], 0x088D6A466   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartProfile:
    mov dword ptr [currentHash + RIP], 0x0FC240D70   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStopProfile:
    mov dword ptr [currentHash + RIP], 0x0049DC2C0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSubscribeWnfStateChange:
    mov dword ptr [currentHash + RIP], 0x0FFBE08E3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendProcess:
    mov dword ptr [currentHash + RIP], 0x0FC20DBBD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSuspendThread:
    mov dword ptr [currentHash + RIP], 0x0301F3CB6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSystemDebugControl:
    mov dword ptr [currentHash + RIP], 0x0C09401C2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateEnclave:
    mov dword ptr [currentHash + RIP], 0x0FB9B1A17   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTerminateJobObject:
    mov dword ptr [currentHash + RIP], 0x0F451E4CD   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTestAlert:
    mov dword ptr [currentHash + RIP], 0x04CCE691E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawRegistry:
    mov dword ptr [currentHash + RIP], 0x01A8E0C1F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtThawTransactions:
    mov dword ptr [currentHash + RIP], 0x0F6A4904F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTraceControl:
    mov dword ptr [currentHash + RIP], 0x073AC7F4F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtTranslateFilePath:
    mov dword ptr [currentHash + RIP], 0x09A144750   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUmsThreadYield:
    mov dword ptr [currentHash + RIP], 0x0A79B76AF   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadDriver:
    mov dword ptr [currentHash + RIP], 0x036A713F4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey:
    mov dword ptr [currentHash + RIP], 0x0AC00B581   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKey2:
    mov dword ptr [currentHash + RIP], 0x02DACC778   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnloadKeyEx:
    mov dword ptr [currentHash + RIP], 0x093812F45   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockFile:
    mov dword ptr [currentHash + RIP], 0x0D960EF3B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnlockVirtualMemory:
    mov dword ptr [currentHash + RIP], 0x0001260FC   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnmapViewOfSectionEx:
    mov dword ptr [currentHash + RIP], 0x052D09268   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUnsubscribeWnfStateChange:
    mov dword ptr [currentHash + RIP], 0x08425F188   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtUpdateWnfStateData:
    mov dword ptr [currentHash + RIP], 0x0FC4209D8   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtVdmControl:
    mov dword ptr [currentHash + RIP], 0x00751C1FB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForAlertByThreadId:
    mov dword ptr [currentHash + RIP], 0x060B6106A   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForDebugEvent:
    mov dword ptr [currentHash + RIP], 0x00A801B24   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForKeyedEvent:
    mov dword ptr [currentHash + RIP], 0x080AAE94C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWorkViaWorkerFactory:
    mov dword ptr [currentHash + RIP], 0x0871AAFB5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitHighEventPair:
    mov dword ptr [currentHash + RIP], 0x001343783   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitLowEventPair:
    mov dword ptr [currentHash + RIP], 0x01445ED32   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtAcquireCMFViewOwnership:
    mov dword ptr [currentHash + RIP], 0x074AD6802   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCancelDeviceWakeupRequest:
    mov dword ptr [currentHash + RIP], 0x09338D3F4   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearAllSavepointsTransaction:
    mov dword ptr [currentHash + RIP], 0x04CB423A9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtClearSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x0173117A3   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRollbackSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x0C881F62D   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointTransaction:
    mov dword ptr [currentHash + RIP], 0x0DA42DCD5   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSavepointComplete:
    mov dword ptr [currentHash + RIP], 0x0449813B2   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateSectionEx:
    mov dword ptr [currentHash + RIP], 0x050B393E9   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtCreateCrossVmEvent:
    mov dword ptr [currentHash + RIP], 0x0C888CD1E   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtGetPlugPlayEvent:
    mov dword ptr [currentHash + RIP], 0x098B99A2F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtListTransactions:
    mov dword ptr [currentHash + RIP], 0x015B77575   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtMarshallTransaction:
    mov dword ptr [currentHash + RIP], 0x000AA223B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtPullTransaction:
    mov dword ptr [currentHash + RIP], 0x0C02BE6BB   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtReleaseCMFViewOwnership:
    mov dword ptr [currentHash + RIP], 0x0308CDA16   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtWaitForWnfNotifications:
    mov dword ptr [currentHash + RIP], 0x00F952B4F   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtStartTm:
    mov dword ptr [currentHash + RIP], 0x0E24E0535   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtSetInformationProcess:
    mov dword ptr [currentHash + RIP], 0x03994140C   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestDeviceWakeup:
    mov dword ptr [currentHash + RIP], 0x005A52EFE   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtRequestWakeupLatency:
    mov dword ptr [currentHash + RIP], 0x0962DFBC0   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtQuerySystemTime:
    mov dword ptr [currentHash + RIP], 0x0BA3EB39B   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtManageHotPatch:
    mov dword ptr [currentHash + RIP], 0x0130F9C29   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


NtContinueEx:
    mov dword ptr [currentHash + RIP], 0x073722FD6   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


RtlCreateUserThread:
    mov dword ptr [currentHash + RIP], 0x0A808B6B1   # Load function hash into global variable.
    call WhisperMain                           # Resolve function hash into syscall number and make the call


