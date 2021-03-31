.code

EXTERN SW2_GetSyscallNumber: PROC

NtAccessCheck PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C45B3507h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08DAEE74Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 018AF0340h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A36D8931h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 064DED283h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FA60878Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCallbackReturn ENDP

NtReadFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B5139A5Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadFile ENDP

NtDeviceIoControlFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D876A360h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeviceIoControlFile ENDP

NtWriteFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 002981C2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteFile ENDP

NtRemoveIoCompletion PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0930C939Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 018084D38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 062F27B76h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01AB11324h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplyPort ENDP

NtSetInformationThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0554A61D5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationThread ENDP

NtSetEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0298B301Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetEvent ENDP

NtClose PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0049F2513h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClose ENDP

NtQueryObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F8C80384h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryObject ENDP

NtQueryInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 078DC7476h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationFile ENDP

NtOpenKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 064D19FB2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenKey ENDP

NtEnumerateValueKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0964FE5B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateValueKey ENDP

NtFindAtom PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DB5FEA9Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFindAtom ENDP

NtQueryDefaultLocale PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0663754A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDefaultLocale ENDP

NtQueryKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 003C6EE5Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryKey ENDP

NtQueryValueKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02EFF5D05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D9F1913h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0822EA9B3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08F42C8D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DBC4349Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteFileGather ENDP

NtCreateKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0099D4C4Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateKey ENDP

NtFreeVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0039E1B01h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 010B2392Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 080BED298h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReleaseMutant ENDP

NtQueryInformationToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00B990506h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A0F166BBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C985E520h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02B9F1114h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08EA243F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationThread ENDP

NtOpenProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04DD34C5Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcess ENDP

NtSetInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E5B6CB63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationFile ENDP

NtMapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C348C3DAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A8A8A93Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 008C02E49h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00785DBD1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 043DF545Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02E8C321Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 003A00D3Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A8D7876h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0900392B8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 071DA5F7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AEBEBF24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateKey ENDP

NtOpenFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DD7AFB39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenFile ENDP

NtDelayExecution PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D7B017C2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 032B8BA9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04E9E684Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemInformation ENDP

NtOpenSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 056105A8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenSection ENDP

NtQueryTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0EBA776ABh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryTimer ENDP

NtFsControlFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01CBA4F8Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B018A6B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A942A42h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A379A1Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02BB9C0ECh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryAttributesFile ENDP

NtClearEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D289D502h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClearEvent ENDP

NtReadVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 047D37B57h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadVirtualMemory ENDP

NtOpenEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0014B06C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0059B7696h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A580F3A4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDuplicateToken ENDP

NtContinue PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 042C6816Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtContinue ENDP

NtQueryDefaultUILanguage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03B9C0A06h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0389B76B1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueueApcThread ENDP

NtYieldExecution PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CB1FE84Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtYieldExecution ENDP

NtAddAtom PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 094C1936Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAddAtom ENDP

NtCreateEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 076A44700h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 06C3CBC8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00EAC1001h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSection ENDP

NtFlushBuffersFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BF772D41h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04F9965DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0838DD751h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProcessEx ENDP

NtCreateThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07D25AD99h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThread ENDP

NtIsProcessInJob PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0652EB71Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 001911B13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtProtectVirtualMemory ENDP

NtQuerySection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 006DC0841h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySection ENDP

NtResumeThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D2D038Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResumeThread ENDP

NtTerminateThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04EEE5467h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTerminateThread ENDP

NtReadRequestData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 062FC724Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadRequestData ENDP

NtCreateFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AA9825B3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateFile ENDP

NtQueryEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C88E448Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryEvent ENDP

NtWriteRequestData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02084CC8Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0829C9002h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 034AB2E06h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 031A1FEE3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 067584C07h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationObject ENDP

NtCancelIoFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0349DC0D6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelIoFile ENDP

NtTraceEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 038BF1F2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTraceEvent ENDP

NtPowerInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 082099CB9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPowerInformation ENDP

NtSetValueKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 039E4DC86h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetValueKey ENDP

NtCancelTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 005BA93BEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelTimer ENDP

NtSetTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02096B195h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetTimer ENDP

NtAccessCheckByType PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05EF96A36h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 025B92B23h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0165116CEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03B942F24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D89B3687h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 089ABB72Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAddAtomEx ENDP

NtAddBootEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0099CE2FEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAddBootEntry ENDP

NtAddDriverEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00995190Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01CA80A21h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 009910D07h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07ADA206Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlertResumeThread ENDP

NtAlertThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03C073691h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 06FB00378h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 045B13D2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0249E0DC3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0059C0400h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02A91E2CEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0868FC051h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 065B71C39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A396860Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05E80BFDEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0615EDD9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0198C3EDFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 010CB361Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DD58DDF4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D28F143h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036AA2922h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03AA910F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0448F2A4Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004D07937h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07EE2796Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 065307C9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D172F2DDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 024752FEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07DA3440Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 069496FEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D54CD5DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03D1E2E8Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0922C6144h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FD76E6F9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E076E2DBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F2340C6Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0755F4DF3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00FA93506h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09B3FF9B5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCallEnclave ENDP

NtCancelIoFileEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0504BA231h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 002BB8AACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BBBF56A1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 099BCBB22h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 006A3000Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCommitComplete ENDP

NtCommitEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05FC97E7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0144FF61Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0408A4217h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCommitTransaction ENDP

NtCompactKeys PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B315A882h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompactKeys ENDP

NtCompareObjects PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0041B70C3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompareObjects ENDP

NtCompareSigningLevels PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0248A241Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompareSigningLevels ENDP

NtCompareTokens PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 017BB0CD3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompareTokens ENDP

NtCompleteConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02E71DDFEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompleteConnectPort ENDP

NtCompressKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09700ACBCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCompressKey ENDP

NtConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0EA8DC112h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07FF6091Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BCB7DC63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0EC58C48Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 024D4E78Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CE2EA924h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateEnclave ENDP

NtCreateEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A410BD7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateEnlistment ENDP

NtCreateEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004B04C65h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateEventPair ENDP

NtCreateIRTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 033A00518h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03AA41A2Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 008A7183Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateJobObject ENDP

NtCreateJobSet PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BD398F86h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07CDFA562h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09E045956h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09E54025Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07FC4B571h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateMailslotFile ENDP

NtCreateMutant PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0872186B5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E8482C12h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 016B9C982h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreatePagingFile ENDP

NtCreatePartition PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08AD38843h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreatePartition ENDP

NtCreatePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A6F258F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 019B5D21Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0319E3010h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProcess ENDP

NtCreateProfile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036A14072h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProfile ENDP

NtCreateProfileEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07CD28AACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0991EC1D0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0029EC5D4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CB4BF5C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0163860C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 046BC3042h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

NtCreateTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 074575104h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateTimer ENDP

NtCreateTimer2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07022D1BDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateTimer2 ENDP

NtCreateToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00C312A9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateToken ENDP

NtCreateTokenEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B8ABF810h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateTokenEx ENDP

NtCreateTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05CC5725Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00E2E72C4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00BA7063Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0079A21C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 025403CC4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0853A597Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0088C7A74h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B0335121h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDebugActiveProcess ENDP

NtDebugContinue PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01E94F9D8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDebugContinue ENDP

NtDeleteAtom PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036A3AB92h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0099D0111h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00B960104h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 047C55079h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteFile ENDP

NtDeleteKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E723055Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C12F3BB9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 096B95390h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07DE46C7Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0840E96BEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0921C9FBDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F86AEEDBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDisableLastKnownGood ENDP

NtDisplayString PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00EA14480h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDisplayString ENDP

NtDrawText PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F94CECCDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDrawText ENDP

NtEnableLastKnownGood PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A4325A23h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02490514Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 060C4FAEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07E5F08A1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E4B8EC24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 034AD1679h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtExtendSection ENDP

NtFilterBootOption PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01A347CE4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFilterBootOption ENDP

NtFilterToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C759CDC2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFilterToken ENDP

NtFilterTokenEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08A9B46DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0043650EBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 083D47089h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01FA1491Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushInstructionCache ENDP

NtFlushKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040E45579h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00929CD7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0831C899Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 097A4B5F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 095CFA867h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CC90FC2Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05DC95543h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A0AAC638h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FFB4FD27h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00228450Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 082A56FFFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F75B0B2Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CE55AEDEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01EBC5467h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07DA81C3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetNextProcess ENDP

NtGetNextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F45039F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 039EC2066h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BA67C8ABh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01CC6286Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F15024EBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01EAA5B8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtImpersonateThread ENDP

NtInitializeEnclave PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A6BE8E3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D47DB04h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040DD7651h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09C8AF25Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FCFEE649h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09BA3D91Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtIsUILanguageComitted ENDP

NtListenPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0523E57ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtListenPort ENDP

NtLoadDriver PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0917ECA53h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadDriver ENDP

NtLoadEnclaveData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B6CF43A2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03EE52A56h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadHotPatch ENDP

NtLoadKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0069BF5E0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadKey ENDP

NtLoadKey2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E69DA08Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadKey2 ENDP

NtLoadKeyEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0557A8126h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLoadKeyEx ENDP

NtLockFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02F78CE3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLockFile ENDP

NtLockProductActivationKeys PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02DB72826h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04A6F358Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01D952B1Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BE925D8Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01ABA220Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMakeTemporaryObject ENDP

NtManagePartition PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04C98084Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtManagePartition ENDP

NtMapCMFModule PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036BC2C38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 085BC602Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04093742Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 005AB0B3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00F872514h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 048EA5A42h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02AA9DCD7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09A8EB9D4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00F553C92h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0278C7940h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 079E51BF3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenEnlistment ENDP

NtOpenEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01631DA63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C88E885Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A26F94Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenJobObject ENDP

NtOpenKeyEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 06D623BBDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 056DF5460h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 062BD3666h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C803D790h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05688591Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 016898EA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036A01633h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0173FD413h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 093A37BA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FE57FEC5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00AB2DE90h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040AFA42Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenSemaphore ENDP

NtOpenSession PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09F317D64h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BC26445Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A4783057h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenThread ENDP

NtOpenTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DDB02BD4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenTimer ENDP

NtOpenTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00CA22233h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 035A70126h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0041AE08Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00890003Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05FC11E13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04929BB70h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 076A81142h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F855C1F7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03C52C61Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B638BCA0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01E610EEEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPropagationComplete ENDP

NtPropagationFailed PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04E9E74C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPropagationFailed ENDP

NtPulseEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040836718h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 006AB2134h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0039F9B95h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C7572ACFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F1480645h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 014275CF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02C1F1453h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01BB8695Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BC2B8EBCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DBD9D771h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04CD6B17Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0ED33FA82h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09844E58Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A4BFDDB2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 064F6795Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 027B50F2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00C845229h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03F29D430h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0055D25F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 073EF4472h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00F5D8C44h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0950EB59Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 021203C98h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E95DC8EAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04F6A0EBEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 022D830B9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09860DE9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B9A39E38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0229A520Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 001D01F70h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08858D295h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08651BBE5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08555760Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0009E21C3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0988B0EBFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01035528Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 036D4F4AEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0148A1419h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AEC6509Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0228BE4DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0382B0C96h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueueApcThreadEx ENDP

NtRaiseException PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0990F9595h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRaiseException ENDP

NtRaiseHardError PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FD6CFDFBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00E26CB74h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BB26A1B0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01F06860Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A3606ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 015831310h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DAB3C13Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00F4AF53Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08B77A822h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08092D44Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08423B668h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRemoveProcessDebug ENDP

NtRenameKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 003925840h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRenameKey ENDP

NtRenameTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08E329AAFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRenameTransactionManager ENDP

NtReplaceKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09EDDB571h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03838CA3Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 020BD272Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02ACD0152h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRequestPort ENDP

NtResetEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07EBE4518h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResetEvent ENDP

NtResetWriteWatch PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 074B94E2Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResetWriteWatch ENDP

NtRestoreKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DF5AFCF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRestoreKey ENDP

NtResumeProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DE3CD7A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004AE043Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 069304180h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F196D64Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 094D64F9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00E992005h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08B375614h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 009DAF7ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSaveKey ENDP

NtSaveKeyEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07E75B003h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 021B8DDD2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 026E94576h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSecureConnectPort ENDP

NtSerializeBoot PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 070A0367Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01F3269D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D98B3D1Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0209B2424h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004BB8D6Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0284FAD6Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetContextThread ENDP

NtSetDebugFilterState PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 030B16E0Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0DD71D8DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C7A7FD62h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B58B39A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01F8C8C91h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AEEDFED2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetEaFile ENDP

NtSetHighEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 010B43821h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03CB3D02Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 093AAE962h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040986A45h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07BD27C40h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F8D4C27Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D389FC39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07F1F8F7Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AE38242Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03398F932h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00EE62E75h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AB14E5C8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D963B39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07EEE544Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05C847200h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03553158Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 018DE423Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 02612D21Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004B42C01h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 014B0342Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0ED4A266Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01CB8241Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01483CC3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 06CBE5E05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03EA23835h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07290585Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A4A9B412h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05C9257F2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B5B61520h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetTimer2 ENDP

NtSetTimerEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0130259FFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetTimerEx ENDP

NtSetTimerResolution PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C14E205Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 007ACCF00h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CBDA3ACCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03EAD3B3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C050C9C4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00494706Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09AB569CAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B816D28Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSinglePhaseReject ENDP

NtStartProfile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 004B2DC80h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtStartProfile ENDP

NtStopProfile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F7A6F01Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01E236FFEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05D863A94h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSuspendProcess ENDP

NtSuspendThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F8E372CDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSuspendThread ENDP

NtSystemDebugControl PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0078F011Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0EEB062A2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0269A2407h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTerminateJobObject ENDP

NtTestAlert PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 086D5B57Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTestAlert ENDP

NtThawRegistry PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040AF3E4Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtThawRegistry ENDP

NtThawTransactions PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0019A1971h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtThawTransactions ENDP

NtTraceControl PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00991F3D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTraceControl ENDP

NtTranslateFilePath PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CE10E9DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A73A9CADh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUmsThreadYield ENDP

NtUnloadDriver PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 012BF4E12h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnloadDriver ENDP

NtUnloadKey PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C81F2B67h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnloadKey ENDP

NtUnloadKey2 PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0AFD77AF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0537819C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnloadKeyEx ENDP

NtUnlockFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 06C3E64A8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 003932D05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 032890634h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04F5F1B6Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A23CD4B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUpdateWnfStateData ENDP

NtVdmControl PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04794470Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 05CBE6E69h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0008B0B0Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0D08A3618h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 058F0725Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 027921D3Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C09DC00Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A912008h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 017AAEFA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0000846DDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 012151E8Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 076E950BDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D920904h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSavepointTransaction ENDP

NtSavepointComplete PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BD32253Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSavepointComplete ENDP

NtCreateSectionEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FEAD2DF7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 09CBBA109h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 040CB3F38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 001953933h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtListTransactions ENDP

NtMarshallTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 030AB12FFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMarshallTransaction ENDP

NtPullTransaction PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0178C151Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 058E781AEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00D973101h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForWnfNotifications ENDP

NtStartTm PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0438F257Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtStartTm ENDP

NtSetInformationProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07E337FACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01547D013h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BC18A7B8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08E97AF13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemTime ENDP

NtManageHotPatch PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E4D93065h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtManageHotPatch ENDP

NtContinueEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 053AD7510h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtContinueEx ENDP

end