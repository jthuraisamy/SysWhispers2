#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#define SW2_SEED 0x285E0FAD
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList(void);
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, *PPS_CREATE_STATE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, *PKEY_SET_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, *PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, *PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, *PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, *PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;
		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, *PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, *PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, *PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, *PIO_SESSION_STATE;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, *PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, *PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, *PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, *PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, *PKCONTINUE_ARGUMENT;

EXTERN_C NTSTATUS NtAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus);

EXTERN_C NTSTATUS NtWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL);

EXTERN_C NTSTATUS NtMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS NtCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status);

EXTERN_C NTSTATUS NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage);

EXTERN_C NTSTATUS NtReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

EXTERN_C NTSTATUS NtSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId);

EXTERN_C NTSTATUS NtQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS NtImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message);

EXTERN_C NTSTATUS NtReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS NtAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS NtReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtSetEventBoostPriority(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

EXTERN_C NTSTATUS NtEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options);

EXTERN_C NTSTATUS NtQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtClearEvent(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert);

EXTERN_C NTSTATUS NtQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtYieldExecution();

EXTERN_C NTSTATUS NtAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState);

EXTERN_C NTSTATUS NtQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass);

EXTERN_C NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS NtFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData);

EXTERN_C NTSTATUS NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

EXTERN_C NTSTATUS NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended);

EXTERN_C NTSTATUS NtIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength);

EXTERN_C NTSTATUS NtQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL);

EXTERN_C NTSTATUS NtOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength);

EXTERN_C NTSTATUS NtCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields);

EXTERN_C NTSTATUS NtPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL);

EXTERN_C NTSTATUS NtSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtAcquireProcessActivityReference();

EXTERN_C NTSTATUS NtAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtAlertThread(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtAlertThreadByThreadId(
	IN ULONG ThreadId);

EXTERN_C NTSTATUS NtAllocateLocallyUniqueId(
	OUT PLUID Luid);

EXTERN_C NTSTATUS NtAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type);

EXTERN_C NTSTATUS NtAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray);

EXTERN_C NTSTATUS NtAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed);

EXTERN_C NTSTATUS NtAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection);

EXTERN_C NTSTATUS NtAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext);

EXTERN_C NTSTATUS NtAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize);

EXTERN_C NTSTATUS NtAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId);

EXTERN_C NTSTATUS NtAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes);

EXTERN_C NTSTATUS NtAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute);

EXTERN_C NTSTATUS NtAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle);

EXTERN_C NTSTATUS NtAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId);

EXTERN_C NTSTATUS NtAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase);

EXTERN_C NTSTATUS NtAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags);

EXTERN_C NTSTATUS NtAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile);

EXTERN_C NTSTATUS NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL);

EXTERN_C NTSTATUS NtCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL);

EXTERN_C NTSTATUS NtCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket);

EXTERN_C NTSTATUS NtCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray);

EXTERN_C NTSTATUS NtCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle);

EXTERN_C NTSTATUS NtCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2);

EXTERN_C NTSTATUS NtCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal);

EXTERN_C NTSTATUS NtCompleteConnectPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtCompressKey(
	IN HANDLE Key);

EXTERN_C NTSTATUS NtConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL);

EXTERN_C NTSTATUS NtCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL);

EXTERN_C NTSTATUS NtCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout);

EXTERN_C NTSTATUS NtCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner);

EXTERN_C NTSTATUS NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL);

EXTERN_C NTSTATUS NtCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority);

EXTERN_C NTSTATUS NtCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode);

EXTERN_C NTSTATUS NtCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS NtCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity);

EXTERN_C NTSTATUS NtCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity);

EXTERN_C NTSTATUS NtCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags);

EXTERN_C NTSTATUS NtCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount);

EXTERN_C NTSTATUS NtCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType);

EXTERN_C NTSTATUS NtCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL);

EXTERN_C NTSTATUS NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor);

EXTERN_C NTSTATUS NtCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL);

EXTERN_C NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);

EXTERN_C NTSTATUS NtDeleteAtom(
	IN USHORT Atom);

EXTERN_C NTSTATUS NtDeleteBootEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtDeleteDriverEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtDeleteKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtDeletePrivateNamespace(
	IN HANDLE NamespaceHandle);

EXTERN_C NTSTATUS NtDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName);

EXTERN_C NTSTATUS NtDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL);

EXTERN_C NTSTATUS NtDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtDisableLastKnownGood();

EXTERN_C NTSTATUS NtDisplayString(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtDrawText(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtEnableLastKnownGood();

EXTERN_C NTSTATUS NtEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize);

EXTERN_C NTSTATUS NtFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag);

EXTERN_C NTSTATUS NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtFlushKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtFlushProcessWriteBuffers();

EXTERN_C NTSTATUS NtFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtFlushWriteBuffer();

EXTERN_C NTSTATUS NtFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray);

EXTERN_C NTSTATUS NtFreezeRegistry(
	IN ULONG TimeOutInSeconds);

EXTERN_C NTSTATUS NtFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout);

EXTERN_C NTSTATUS NtGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL);

EXTERN_C NTSTATUS NtGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize);

EXTERN_C NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtGetCurrentProcessorNumber();

EXTERN_C NTSTATUS NtGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL);

EXTERN_C NTSTATUS NtGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State);

EXTERN_C NTSTATUS NtGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData);

EXTERN_C NTSTATUS NtGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle);

EXTERN_C NTSTATUS NtGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle);

EXTERN_C NTSTATUS NtGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize);

EXTERN_C NTSTATUS NtGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL);

EXTERN_C NTSTATUS NtGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity);

EXTERN_C NTSTATUS NtImpersonateAnonymousToken(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos);

EXTERN_C NTSTATUS NtInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize);

EXTERN_C NTSTATUS NtInitializeRegistry(
	IN USHORT BootCondition);

EXTERN_C NTSTATUS NtInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtIsSystemResumeAutomatic();

EXTERN_C NTSTATUS NtIsUILanguageComitted();

EXTERN_C NTSTATUS NtListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest);

EXTERN_C NTSTATUS NtLoadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag);

EXTERN_C NTSTATUS NtLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile);

EXTERN_C NTSTATUS NtLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL);

EXTERN_C NTSTATUS NtLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock);

EXTERN_C NTSTATUS NtLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL);

EXTERN_C NTSTATUS NtLockRegistryKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType);

EXTERN_C NTSTATUS NtMakePermanentObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtMakeTemporaryObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength);

EXTERN_C NTSTATUS NtMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL);

EXTERN_C NTSTATUS NtMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtModifyBootEntry(
	IN PBOOT_ENTRY BootEntry);

EXTERN_C NTSTATUS NtModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL);

EXTERN_C NTSTATUS NtNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize);

EXTERN_C NTSTATUS NtOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL);

EXTERN_C NTSTATUS NtOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL);

EXTERN_C NTSTATUS NtPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength);

EXTERN_C NTSTATUS NtPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result);

EXTERN_C NTSTATUS NtPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer);

EXTERN_C NTSTATUS NtPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus);

EXTERN_C NTSTATUS NtPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency);

EXTERN_C NTSTATUS NtQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength);

EXTERN_C NTSTATUS NtQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level);

EXTERN_C NTSTATUS NtQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL);

EXTERN_C NTSTATUS NtQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId);

EXTERN_C NTSTATUS NtQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval);

EXTERN_C NTSTATUS NtQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize);

EXTERN_C NTSTATUS NtQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount);

EXTERN_C NTSTATUS NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize);

EXTERN_C NTSTATUS NtQueryPortInformationProcess();

EXTERN_C NTSTATUS NtQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded);

EXTERN_C NTSTATUS NtQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6);

EXTERN_C NTSTATUS NtQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime);

EXTERN_C NTSTATUS NtQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize);

EXTERN_C NTSTATUS NtQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize);

EXTERN_C NTSTATUS NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance);

EXTERN_C NTSTATUS NtRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response);

EXTERN_C NTSTATUS NtReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtRecoverResourceManager(
	IN HANDLE ResourceManagerHandle);

EXTERN_C NTSTATUS NtRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle);

EXTERN_C NTSTATUS NtRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL);

EXTERN_C NTSTATUS NtRegisterThreadTerminatePort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable);

EXTERN_C NTSTATUS NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName);

EXTERN_C NTSTATUS NtRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid);

EXTERN_C NTSTATUS NtReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile);

EXTERN_C NTSTATUS NtReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage);

EXTERN_C NTSTATUS NtResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize);

EXTERN_C NTSTATUS NtRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtRevertContainerImpersonation();

EXTERN_C NTSTATUS NtRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format);

EXTERN_C NTSTATUS NtSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtSerializeBoot();

EXTERN_C NTSTATUS NtSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count);

EXTERN_C NTSTATUS NtSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange);

EXTERN_C NTSTATUS NtSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL);

EXTERN_C NTSTATUS NtSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL);

EXTERN_C NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State);

EXTERN_C NTSTATUS NtSetDefaultHardErrorPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId);

EXTERN_C NTSTATUS NtSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count);

EXTERN_C NTSTATUS NtSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize);

EXTERN_C NTSTATUS NtSetHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength);

EXTERN_C NTSTATUS NtSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength);

EXTERN_C NTSTATUS NtSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength);

EXTERN_C NTSTATUS NtSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength);

EXTERN_C NTSTATUS NtSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength);

EXTERN_C NTSTATUS NtSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength);

EXTERN_C NTSTATUS NtSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength);

EXTERN_C NTSTATUS NtSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength);

EXTERN_C NTSTATUS NtSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source);

EXTERN_C NTSTATUS NtSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered);

EXTERN_C NTSTATUS NtSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation);

EXTERN_C NTSTATUS NtSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi);

EXTERN_C NTSTATUS NtSetLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length);

EXTERN_C NTSTATUS NtSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes);

EXTERN_C NTSTATUS NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength);

EXTERN_C NTSTATUS NtSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL);

EXTERN_C NTSTATUS NtSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState);

EXTERN_C NTSTATUS NtSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength);

EXTERN_C NTSTATUS NtSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution);

EXTERN_C NTSTATUS NtSetUuidSeed(
	IN PUCHAR Seed);

EXTERN_C NTSTATUS NtSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass);

EXTERN_C NTSTATUS NtSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent);

EXTERN_C NTSTATUS NtShutdownSystem(
	IN SHUTDOWN_ACTION Action);

EXTERN_C NTSTATUS NtShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount);

EXTERN_C NTSTATUS NtSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL);

EXTERN_C NTSTATUS NtSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtStartProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtStopProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL);

EXTERN_C NTSTATUS NtSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS NtSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread);

EXTERN_C NTSTATUS NtTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtTestAlert();

EXTERN_C NTSTATUS NtThawRegistry();

EXTERN_C NTSTATUS NtThawTransactions();

EXTERN_C NTSTATUS NtTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL);

EXTERN_C NTSTATUS NtUmsThreadYield(
	IN PVOID SchedulerParam);

EXTERN_C NTSTATUS NtUnloadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName);

EXTERN_C NTSTATUS NtUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL);

EXTERN_C NTSTATUS NtUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key);

EXTERN_C NTSTATUS NtUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN PSIZE_T NumberOfBytesToUnlock,
	IN ULONG LockType);

EXTERN_C NTSTATUS NtUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp);

EXTERN_C NTSTATUS NtVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData);

EXTERN_C NTSTATUS NtWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange);

EXTERN_C NTSTATUS NtWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket);

EXTERN_C NTSTATUS NtWaitHighEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtWaitLowEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting);

EXTERN_C NTSTATUS NtCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId);

EXTERN_C NTSTATUS NtSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount);

EXTERN_C NTSTATUS NtCreateCrossVmEvent();

EXTERN_C NTSTATUS NtGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize);

EXTERN_C NTSTATUS NtListTransactions();

EXTERN_C NTSTATUS NtMarshallTransaction();

EXTERN_C NTSTATUS NtPullTransaction();

EXTERN_C NTSTATUS NtReleaseCMFViewOwnership();

EXTERN_C NTSTATUS NtWaitForWnfNotifications();

EXTERN_C NTSTATUS NtStartTm();

EXTERN_C NTSTATUS NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length);

EXTERN_C NTSTATUS NtRequestDeviceWakeup(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtRequestWakeupLatency(
	IN ULONG LatencyTime);

EXTERN_C NTSTATUS NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime);

EXTERN_C NTSTATUS NtManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtContinueEx(
	IN PCONTEXT ContextRecord,
	IN PKCONTINUE_ARGUMENT ContinueArgument);

#endif


#include "Syscalls.h"
#include <time.h>
#include <stdint.h>

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList = { 0, 1 };

#ifdef RANDSYSCALL
#ifndef _WIN64
uint32_t ntdllBase = 0;
#else
uint64_t ntdllBase = 0;
#endif
#endif

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList(void)
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

#if defined(_WIN64)
    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
#else
    PSW2_PEB Peb = (PSW2_PEB)__readfsdword(0x30);
#endif
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;
    
#ifdef RANDSYSCALL
#ifdef _WIN64
    ntdllBase = (uint64_t)DllBase;
#else
    ntdllBase = (uint64_t)DllBase;
#endif
#endif

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

#ifdef RANDSYSCALL
#ifdef _WIN64
EXTERN_C uint64_t SW2_GetRandomSyscallAddress(void)
#else
EXTERN_C DWORD SW2_GetRandomSyscallAddress(int callType)
#endif
{
    int instructOffset = 0;
    int instructValue = 0;
#ifndef _WIN64
    // Wow64
    if (callType == 0)
    {
        instructOffset = 0x05;
        instructValue = 0x0E8;
    }
    // x86
    else if (callType == 1)
    {
        instructOffset = 0x05;
        instructValue = 0x0BA;
    }
#else
    instructOffset = 0x12;
    instructValue = 0x0F;
#endif
    srand(time(0));
    do
    {
        int randNum = (rand() % (SW2_SyscallList.Count + 1));
        if (*(unsigned char*)(ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset) == instructValue)
            return (ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset);
    } while(1);
}
#endif


#define WhisperMain
__asm__(".intel_syntax noprefix \n\
.global WhisperMain \n\
WhisperMain: \n\
    pop rax \n\
    mov [rsp+ 8], rcx \n\
    mov [rsp+16], rdx \n\
    mov [rsp+24], r8 \n\
    mov [rsp+32], r9 \n\
    sub rsp, 0x28 \n\
    mov rcx, r10 \n\
    call SW2_GetSyscallNumber \n\
    add rsp, 0x28 \n\
    mov rcx, [rsp+ 8] \n\
    mov rdx, [rsp+16] \n\
    mov r8, [rsp+24] \n\
    mov r9, [rsp+32] \n\
    mov r10, rcx \n\
    syscall \n\
    ret \n\
");

#define ZwAccessCheck NtAccessCheck
__asm__(".intel_syntax noprefix \n\
NtAccessCheck: \n\
    mov r10, 0x018A0737D \n\
    call WhisperMain \n\
");


#define ZwWorkerFactoryWorkerReady NtWorkerFactoryWorkerReady
__asm__(".intel_syntax noprefix \n\
NtWorkerFactoryWorkerReady: \n\
    mov r10, 0x09BA97DB3 \n\
    call WhisperMain \n\
");


#define ZwAcceptConnectPort NtAcceptConnectPort
__asm__(".intel_syntax noprefix \n\
NtAcceptConnectPort: \n\
    mov r10, 0x068B11B5E \n\
    call WhisperMain \n\
");


#define ZwMapUserPhysicalPagesScatter NtMapUserPhysicalPagesScatter
__asm__(".intel_syntax noprefix \n\
NtMapUserPhysicalPagesScatter: \n\
    mov r10, 0x07FEE1137 \n\
    call WhisperMain \n\
");


#define ZwWaitForSingleObject NtWaitForSingleObject
__asm__(".intel_syntax noprefix \n\
NtWaitForSingleObject: \n\
    mov r10, 0x090BFA003 \n\
    call WhisperMain \n\
");


#define ZwCallbackReturn NtCallbackReturn
__asm__(".intel_syntax noprefix \n\
NtCallbackReturn: \n\
    mov r10, 0x01E941D38 \n\
    call WhisperMain \n\
");


#define ZwReadFile NtReadFile
__asm__(".intel_syntax noprefix \n\
NtReadFile: \n\
    mov r10, 0x0EA79D8E0 \n\
    call WhisperMain \n\
");


#define ZwDeviceIoControlFile NtDeviceIoControlFile
__asm__(".intel_syntax noprefix \n\
NtDeviceIoControlFile: \n\
    mov r10, 0x07CF8ADCC \n\
    call WhisperMain \n\
");


#define ZwWriteFile NtWriteFile
__asm__(".intel_syntax noprefix \n\
NtWriteFile: \n\
    mov r10, 0x059C9C8FD \n\
    call WhisperMain \n\
");


#define ZwRemoveIoCompletion NtRemoveIoCompletion
__asm__(".intel_syntax noprefix \n\
NtRemoveIoCompletion: \n\
    mov r10, 0x00E886E1F \n\
    call WhisperMain \n\
");


#define ZwReleaseSemaphore NtReleaseSemaphore
__asm__(".intel_syntax noprefix \n\
NtReleaseSemaphore: \n\
    mov r10, 0x044960E3A \n\
    call WhisperMain \n\
");


#define ZwReplyWaitReceivePort NtReplyWaitReceivePort
__asm__(".intel_syntax noprefix \n\
NtReplyWaitReceivePort: \n\
    mov r10, 0x05930A25F \n\
    call WhisperMain \n\
");


#define ZwReplyPort NtReplyPort
__asm__(".intel_syntax noprefix \n\
NtReplyPort: \n\
    mov r10, 0x02EBC2B22 \n\
    call WhisperMain \n\
");


#define ZwSetInformationThread NtSetInformationThread
__asm__(".intel_syntax noprefix \n\
NtSetInformationThread: \n\
    mov r10, 0x0340FF225 \n\
    call WhisperMain \n\
");


#define ZwSetEvent NtSetEvent
__asm__(".intel_syntax noprefix \n\
NtSetEvent: \n\
    mov r10, 0x008921512 \n\
    call WhisperMain \n\
");


#define ZwClose NtClose
__asm__(".intel_syntax noprefix \n\
NtClose: \n\
    mov r10, 0x04495DDA1 \n\
    call WhisperMain \n\
");


#define ZwQueryObject NtQueryObject
__asm__(".intel_syntax noprefix \n\
NtQueryObject: \n\
    mov r10, 0x006286085 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationFile NtQueryInformationFile
__asm__(".intel_syntax noprefix \n\
NtQueryInformationFile: \n\
    mov r10, 0x093356B21 \n\
    call WhisperMain \n\
");


#define ZwOpenKey NtOpenKey
__asm__(".intel_syntax noprefix \n\
NtOpenKey: \n\
    mov r10, 0x0720A7393 \n\
    call WhisperMain \n\
");


#define ZwEnumerateValueKey NtEnumerateValueKey
__asm__(".intel_syntax noprefix \n\
NtEnumerateValueKey: \n\
    mov r10, 0x0DA9ADD04 \n\
    call WhisperMain \n\
");


#define ZwFindAtom NtFindAtom
__asm__(".intel_syntax noprefix \n\
NtFindAtom: \n\
    mov r10, 0x0322317BA \n\
    call WhisperMain \n\
");


#define ZwQueryDefaultLocale NtQueryDefaultLocale
__asm__(".intel_syntax noprefix \n\
NtQueryDefaultLocale: \n\
    mov r10, 0x011287BAF \n\
    call WhisperMain \n\
");


#define ZwQueryKey NtQueryKey
__asm__(".intel_syntax noprefix \n\
NtQueryKey: \n\
    mov r10, 0x0A672CB80 \n\
    call WhisperMain \n\
");


#define ZwQueryValueKey NtQueryValueKey
__asm__(".intel_syntax noprefix \n\
NtQueryValueKey: \n\
    mov r10, 0x0982089B9 \n\
    call WhisperMain \n\
");


#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtAllocateVirtualMemory: \n\
    mov r10, 0x0C1512DC6 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__(".intel_syntax noprefix \n\
NtQueryInformationProcess: \n\
    mov r10, 0x0519E7C0E \n\
    call WhisperMain \n\
");


#define ZwWaitForMultipleObjects32 NtWaitForMultipleObjects32
__asm__(".intel_syntax noprefix \n\
NtWaitForMultipleObjects32: \n\
    mov r10, 0x03EAC1F7B \n\
    call WhisperMain \n\
");


#define ZwWriteFileGather NtWriteFileGather
__asm__(".intel_syntax noprefix \n\
NtWriteFileGather: \n\
    mov r10, 0x0318CE8A7 \n\
    call WhisperMain \n\
");


#define ZwCreateKey NtCreateKey
__asm__(".intel_syntax noprefix \n\
NtCreateKey: \n\
    mov r10, 0x0104523FE \n\
    call WhisperMain \n\
");


#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtFreeVirtualMemory: \n\
    mov r10, 0x001930F05 \n\
    call WhisperMain \n\
");


#define ZwImpersonateClientOfPort NtImpersonateClientOfPort
__asm__(".intel_syntax noprefix \n\
NtImpersonateClientOfPort: \n\
    mov r10, 0x0396D26E6 \n\
    call WhisperMain \n\
");


#define ZwReleaseMutant NtReleaseMutant
__asm__(".intel_syntax noprefix \n\
NtReleaseMutant: \n\
    mov r10, 0x0BB168A93 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationToken NtQueryInformationToken
__asm__(".intel_syntax noprefix \n\
NtQueryInformationToken: \n\
    mov r10, 0x08B9FF70C \n\
    call WhisperMain \n\
");


#define ZwRequestWaitReplyPort NtRequestWaitReplyPort
__asm__(".intel_syntax noprefix \n\
NtRequestWaitReplyPort: \n\
    mov r10, 0x020B04558 \n\
    call WhisperMain \n\
");


#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtQueryVirtualMemory: \n\
    mov r10, 0x079917101 \n\
    call WhisperMain \n\
");


#define ZwOpenThreadToken NtOpenThreadToken
__asm__(".intel_syntax noprefix \n\
NtOpenThreadToken: \n\
    mov r10, 0x0FB531910 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationThread NtQueryInformationThread
__asm__(".intel_syntax noprefix \n\
NtQueryInformationThread: \n\
    mov r10, 0x0144CD773 \n\
    call WhisperMain \n\
");


#define ZwOpenProcess NtOpenProcess
__asm__(".intel_syntax noprefix \n\
NtOpenProcess: \n\
    mov r10, 0x0CE2CC5B1 \n\
    call WhisperMain \n\
");


#define ZwSetInformationFile NtSetInformationFile
__asm__(".intel_syntax noprefix \n\
NtSetInformationFile: \n\
    mov r10, 0x02D7D51A9 \n\
    call WhisperMain \n\
");


#define ZwMapViewOfSection NtMapViewOfSection
__asm__(".intel_syntax noprefix \n\
NtMapViewOfSection: \n\
    mov r10, 0x060C9AE95 \n\
    call WhisperMain \n\
");


#define ZwAccessCheckAndAuditAlarm NtAccessCheckAndAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtAccessCheckAndAuditAlarm: \n\
    mov r10, 0x030971C08 \n\
    call WhisperMain \n\
");


#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__(".intel_syntax noprefix \n\
NtUnmapViewOfSection: \n\
    mov r10, 0x008E02671 \n\
    call WhisperMain \n\
");


#define ZwReplyWaitReceivePortEx NtReplyWaitReceivePortEx
__asm__(".intel_syntax noprefix \n\
NtReplyWaitReceivePortEx: \n\
    mov r10, 0x0756F27B5 \n\
    call WhisperMain \n\
");


#define ZwTerminateProcess NtTerminateProcess
__asm__(".intel_syntax noprefix \n\
NtTerminateProcess: \n\
    mov r10, 0x0C337DE9E \n\
    call WhisperMain \n\
");


#define ZwSetEventBoostPriority NtSetEventBoostPriority
__asm__(".intel_syntax noprefix \n\
NtSetEventBoostPriority: \n\
    mov r10, 0x0D88FCC04 \n\
    call WhisperMain \n\
");


#define ZwReadFileScatter NtReadFileScatter
__asm__(".intel_syntax noprefix \n\
NtReadFileScatter: \n\
    mov r10, 0x005AC0D37 \n\
    call WhisperMain \n\
");


#define ZwOpenThreadTokenEx NtOpenThreadTokenEx
__asm__(".intel_syntax noprefix \n\
NtOpenThreadTokenEx: \n\
    mov r10, 0x05A433EBE \n\
    call WhisperMain \n\
");


#define ZwOpenProcessTokenEx NtOpenProcessTokenEx
__asm__(".intel_syntax noprefix \n\
NtOpenProcessTokenEx: \n\
    mov r10, 0x064B1500C \n\
    call WhisperMain \n\
");


#define ZwQueryPerformanceCounter NtQueryPerformanceCounter
__asm__(".intel_syntax noprefix \n\
NtQueryPerformanceCounter: \n\
    mov r10, 0x07BED8581 \n\
    call WhisperMain \n\
");


#define ZwEnumerateKey NtEnumerateKey
__asm__(".intel_syntax noprefix \n\
NtEnumerateKey: \n\
    mov r10, 0x0761F6184 \n\
    call WhisperMain \n\
");


#define ZwOpenFile NtOpenFile
__asm__(".intel_syntax noprefix \n\
NtOpenFile: \n\
    mov r10, 0x0EA58F2EA \n\
    call WhisperMain \n\
");


#define ZwDelayExecution NtDelayExecution
__asm__(".intel_syntax noprefix \n\
NtDelayExecution: \n\
    mov r10, 0x01AB51B26 \n\
    call WhisperMain \n\
");


#define ZwQueryDirectoryFile NtQueryDirectoryFile
__asm__(".intel_syntax noprefix \n\
NtQueryDirectoryFile: \n\
    mov r10, 0x0A8E240B0 \n\
    call WhisperMain \n\
");


#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__(".intel_syntax noprefix \n\
NtQuerySystemInformation: \n\
    mov r10, 0x0228A241F \n\
    call WhisperMain \n\
");


#define ZwOpenSection NtOpenSection
__asm__(".intel_syntax noprefix \n\
NtOpenSection: \n\
    mov r10, 0x08B23AB8E \n\
    call WhisperMain \n\
");


#define ZwQueryTimer NtQueryTimer
__asm__(".intel_syntax noprefix \n\
NtQueryTimer: \n\
    mov r10, 0x0C99AF150 \n\
    call WhisperMain \n\
");


#define ZwFsControlFile NtFsControlFile
__asm__(".intel_syntax noprefix \n\
NtFsControlFile: \n\
    mov r10, 0x03895E81C \n\
    call WhisperMain \n\
");


#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtWriteVirtualMemory: \n\
    mov r10, 0x09B70CDAF \n\
    call WhisperMain \n\
");


#define ZwCloseObjectAuditAlarm NtCloseObjectAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtCloseObjectAuditAlarm: \n\
    mov r10, 0x016DB99C4 \n\
    call WhisperMain \n\
");


#define ZwDuplicateObject NtDuplicateObject
__asm__(".intel_syntax noprefix \n\
NtDuplicateObject: \n\
    mov r10, 0x02C050459 \n\
    call WhisperMain \n\
");


#define ZwQueryAttributesFile NtQueryAttributesFile
__asm__(".intel_syntax noprefix \n\
NtQueryAttributesFile: \n\
    mov r10, 0x0A6B5C6B2 \n\
    call WhisperMain \n\
");


#define ZwClearEvent NtClearEvent
__asm__(".intel_syntax noprefix \n\
NtClearEvent: \n\
    mov r10, 0x07EA59CF0 \n\
    call WhisperMain \n\
");


#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtReadVirtualMemory: \n\
    mov r10, 0x03191351D \n\
    call WhisperMain \n\
");


#define ZwOpenEvent NtOpenEvent
__asm__(".intel_syntax noprefix \n\
NtOpenEvent: \n\
    mov r10, 0x0183371AE \n\
    call WhisperMain \n\
");


#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__(".intel_syntax noprefix \n\
NtAdjustPrivilegesToken: \n\
    mov r10, 0x06DDD5958 \n\
    call WhisperMain \n\
");


#define ZwDuplicateToken NtDuplicateToken
__asm__(".intel_syntax noprefix \n\
NtDuplicateToken: \n\
    mov r10, 0x08350ADCC \n\
    call WhisperMain \n\
");


#define ZwContinue NtContinue
__asm__(".intel_syntax noprefix \n\
NtContinue: \n\
    mov r10, 0x02EA07164 \n\
    call WhisperMain \n\
");


#define ZwQueryDefaultUILanguage NtQueryDefaultUILanguage
__asm__(".intel_syntax noprefix \n\
NtQueryDefaultUILanguage: \n\
    mov r10, 0x055D63014 \n\
    call WhisperMain \n\
");


#define ZwQueueApcThread NtQueueApcThread
__asm__(".intel_syntax noprefix \n\
NtQueueApcThread: \n\
    mov r10, 0x03CA43609 \n\
    call WhisperMain \n\
");


#define ZwYieldExecution NtYieldExecution
__asm__(".intel_syntax noprefix \n\
NtYieldExecution: \n\
    mov r10, 0x018B23A23 \n\
    call WhisperMain \n\
");


#define ZwAddAtom NtAddAtom
__asm__(".intel_syntax noprefix \n\
NtAddAtom: \n\
    mov r10, 0x03FB57C63 \n\
    call WhisperMain \n\
");


#define ZwCreateEvent NtCreateEvent
__asm__(".intel_syntax noprefix \n\
NtCreateEvent: \n\
    mov r10, 0x011B0FFAA \n\
    call WhisperMain \n\
");


#define ZwQueryVolumeInformationFile NtQueryVolumeInformationFile
__asm__(".intel_syntax noprefix \n\
NtQueryVolumeInformationFile: \n\
    mov r10, 0x03575CE31 \n\
    call WhisperMain \n\
");


#define ZwCreateSection NtCreateSection
__asm__(".intel_syntax noprefix \n\
NtCreateSection: \n\
    mov r10, 0x0249304C1 \n\
    call WhisperMain \n\
");


#define ZwFlushBuffersFile NtFlushBuffersFile
__asm__(".intel_syntax noprefix \n\
NtFlushBuffersFile: \n\
    mov r10, 0x01D5C1AC4 \n\
    call WhisperMain \n\
");


#define ZwApphelpCacheControl NtApphelpCacheControl
__asm__(".intel_syntax noprefix \n\
NtApphelpCacheControl: \n\
    mov r10, 0x034624AA3 \n\
    call WhisperMain \n\
");


#define ZwCreateProcessEx NtCreateProcessEx
__asm__(".intel_syntax noprefix \n\
NtCreateProcessEx: \n\
    mov r10, 0x011B3E1CB \n\
    call WhisperMain \n\
");


#define ZwCreateThread NtCreateThread
__asm__(".intel_syntax noprefix \n\
NtCreateThread: \n\
    mov r10, 0x0922FDC85 \n\
    call WhisperMain \n\
");


#define ZwIsProcessInJob NtIsProcessInJob
__asm__(".intel_syntax noprefix \n\
NtIsProcessInJob: \n\
    mov r10, 0x0A8D15C80 \n\
    call WhisperMain \n\
");


#define ZwProtectVirtualMemory NtProtectVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtProtectVirtualMemory: \n\
    mov r10, 0x08792CB57 \n\
    call WhisperMain \n\
");


#define ZwQuerySection NtQuerySection
__asm__(".intel_syntax noprefix \n\
NtQuerySection: \n\
    mov r10, 0x01A8C5E27 \n\
    call WhisperMain \n\
");


#define ZwResumeThread NtResumeThread
__asm__(".intel_syntax noprefix \n\
NtResumeThread: \n\
    mov r10, 0x06AC0665F \n\
    call WhisperMain \n\
");


#define ZwTerminateThread NtTerminateThread
__asm__(".intel_syntax noprefix \n\
NtTerminateThread: \n\
    mov r10, 0x02A0B34A9 \n\
    call WhisperMain \n\
");


#define ZwReadRequestData NtReadRequestData
__asm__(".intel_syntax noprefix \n\
NtReadRequestData: \n\
    mov r10, 0x02E83F03C \n\
    call WhisperMain \n\
");


#define ZwCreateFile NtCreateFile
__asm__(".intel_syntax noprefix \n\
NtCreateFile: \n\
    mov r10, 0x06756F762 \n\
    call WhisperMain \n\
");


#define ZwQueryEvent NtQueryEvent
__asm__(".intel_syntax noprefix \n\
NtQueryEvent: \n\
    mov r10, 0x08000E5E6 \n\
    call WhisperMain \n\
");


#define ZwWriteRequestData NtWriteRequestData
__asm__(".intel_syntax noprefix \n\
NtWriteRequestData: \n\
    mov r10, 0x0621E52D0 \n\
    call WhisperMain \n\
");


#define ZwOpenDirectoryObject NtOpenDirectoryObject
__asm__(".intel_syntax noprefix \n\
NtOpenDirectoryObject: \n\
    mov r10, 0x02A353AA9 \n\
    call WhisperMain \n\
");


#define ZwAccessCheckByTypeAndAuditAlarm NtAccessCheckByTypeAndAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtAccessCheckByTypeAndAuditAlarm: \n\
    mov r10, 0x00C53C00C \n\
    call WhisperMain \n\
");


#define ZwWaitForMultipleObjects NtWaitForMultipleObjects
__asm__(".intel_syntax noprefix \n\
NtWaitForMultipleObjects: \n\
    mov r10, 0x051256B89 \n\
    call WhisperMain \n\
");


#define ZwSetInformationObject NtSetInformationObject
__asm__(".intel_syntax noprefix \n\
NtSetInformationObject: \n\
    mov r10, 0x03C1704BB \n\
    call WhisperMain \n\
");


#define ZwCancelIoFile NtCancelIoFile
__asm__(".intel_syntax noprefix \n\
NtCancelIoFile: \n\
    mov r10, 0x008B94C02 \n\
    call WhisperMain \n\
");


#define ZwTraceEvent NtTraceEvent
__asm__(".intel_syntax noprefix \n\
NtTraceEvent: \n\
    mov r10, 0x02EB52126 \n\
    call WhisperMain \n\
");


#define ZwPowerInformation NtPowerInformation
__asm__(".intel_syntax noprefix \n\
NtPowerInformation: \n\
    mov r10, 0x06688641D \n\
    call WhisperMain \n\
");


#define ZwSetValueKey NtSetValueKey
__asm__(".intel_syntax noprefix \n\
NtSetValueKey: \n\
    mov r10, 0x0E9392F67 \n\
    call WhisperMain \n\
");


#define ZwCancelTimer NtCancelTimer
__asm__(".intel_syntax noprefix \n\
NtCancelTimer: \n\
    mov r10, 0x0178326C0 \n\
    call WhisperMain \n\
");


#define ZwSetTimer NtSetTimer
__asm__(".intel_syntax noprefix \n\
NtSetTimer: \n\
    mov r10, 0x01DC52886 \n\
    call WhisperMain \n\
");


#define ZwAccessCheckByType NtAccessCheckByType
__asm__(".intel_syntax noprefix \n\
NtAccessCheckByType: \n\
    mov r10, 0x0DC56E104 \n\
    call WhisperMain \n\
");


#define ZwAccessCheckByTypeResultList NtAccessCheckByTypeResultList
__asm__(".intel_syntax noprefix \n\
NtAccessCheckByTypeResultList: \n\
    mov r10, 0x0C972F3DC \n\
    call WhisperMain \n\
");


#define ZwAccessCheckByTypeResultListAndAuditAlarm NtAccessCheckByTypeResultListAndAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtAccessCheckByTypeResultListAndAuditAlarm: \n\
    mov r10, 0x0C55AC9C5 \n\
    call WhisperMain \n\
");


#define ZwAccessCheckByTypeResultListAndAuditAlarmByHandle NtAccessCheckByTypeResultListAndAuditAlarmByHandle
__asm__(".intel_syntax noprefix \n\
NtAccessCheckByTypeResultListAndAuditAlarmByHandle: \n\
    mov r10, 0x0C85426DF \n\
    call WhisperMain \n\
");


#define ZwAcquireProcessActivityReference NtAcquireProcessActivityReference
__asm__(".intel_syntax noprefix \n\
NtAcquireProcessActivityReference: \n\
    mov r10, 0x01683D82A \n\
    call WhisperMain \n\
");


#define ZwAddAtomEx NtAddAtomEx
__asm__(".intel_syntax noprefix \n\
NtAddAtomEx: \n\
    mov r10, 0x041A9E191 \n\
    call WhisperMain \n\
");


#define ZwAddBootEntry NtAddBootEntry
__asm__(".intel_syntax noprefix \n\
NtAddBootEntry: \n\
    mov r10, 0x0458B7B2C \n\
    call WhisperMain \n\
");


#define ZwAddDriverEntry NtAddDriverEntry
__asm__(".intel_syntax noprefix \n\
NtAddDriverEntry: \n\
    mov r10, 0x00F972544 \n\
    call WhisperMain \n\
");


#define ZwAdjustGroupsToken NtAdjustGroupsToken
__asm__(".intel_syntax noprefix \n\
NtAdjustGroupsToken: \n\
    mov r10, 0x03D891114 \n\
    call WhisperMain \n\
");


#define ZwAdjustTokenClaimsAndDeviceGroups NtAdjustTokenClaimsAndDeviceGroups
__asm__(".intel_syntax noprefix \n\
NtAdjustTokenClaimsAndDeviceGroups: \n\
    mov r10, 0x07FE55ABD \n\
    call WhisperMain \n\
");


#define ZwAlertResumeThread NtAlertResumeThread
__asm__(".intel_syntax noprefix \n\
NtAlertResumeThread: \n\
    mov r10, 0x01CB2020B \n\
    call WhisperMain \n\
");


#define ZwAlertThread NtAlertThread
__asm__(".intel_syntax noprefix \n\
NtAlertThread: \n\
    mov r10, 0x0380734AE \n\
    call WhisperMain \n\
");


#define ZwAlertThreadByThreadId NtAlertThreadByThreadId
__asm__(".intel_syntax noprefix \n\
NtAlertThreadByThreadId: \n\
    mov r10, 0x009133583 \n\
    call WhisperMain \n\
");


#define ZwAllocateLocallyUniqueId NtAllocateLocallyUniqueId
__asm__(".intel_syntax noprefix \n\
NtAllocateLocallyUniqueId: \n\
    mov r10, 0x049AA1A9D \n\
    call WhisperMain \n\
");


#define ZwAllocateReserveObject NtAllocateReserveObject
__asm__(".intel_syntax noprefix \n\
NtAllocateReserveObject: \n\
    mov r10, 0x03C8415D9 \n\
    call WhisperMain \n\
");


#define ZwAllocateUserPhysicalPages NtAllocateUserPhysicalPages
__asm__(".intel_syntax noprefix \n\
NtAllocateUserPhysicalPages: \n\
    mov r10, 0x0FE65D1FF \n\
    call WhisperMain \n\
");


#define ZwAllocateUuids NtAllocateUuids
__asm__(".intel_syntax noprefix \n\
NtAllocateUuids: \n\
    mov r10, 0x0110A3997 \n\
    call WhisperMain \n\
");


#define ZwAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx
__asm__(".intel_syntax noprefix \n\
NtAllocateVirtualMemoryEx: \n\
    mov r10, 0x06C973072 \n\
    call WhisperMain \n\
");


#define ZwAlpcAcceptConnectPort NtAlpcAcceptConnectPort
__asm__(".intel_syntax noprefix \n\
NtAlpcAcceptConnectPort: \n\
    mov r10, 0x010B1033E \n\
    call WhisperMain \n\
");


#define ZwAlpcCancelMessage NtAlpcCancelMessage
__asm__(".intel_syntax noprefix \n\
NtAlpcCancelMessage: \n\
    mov r10, 0x061550348 \n\
    call WhisperMain \n\
");


#define ZwAlpcConnectPort NtAlpcConnectPort
__asm__(".intel_syntax noprefix \n\
NtAlpcConnectPort: \n\
    mov r10, 0x01E8F2520 \n\
    call WhisperMain \n\
");


#define ZwAlpcConnectPortEx NtAlpcConnectPortEx
__asm__(".intel_syntax noprefix \n\
NtAlpcConnectPortEx: \n\
    mov r10, 0x033AE7155 \n\
    call WhisperMain \n\
");


#define ZwAlpcCreatePort NtAlpcCreatePort
__asm__(".intel_syntax noprefix \n\
NtAlpcCreatePort: \n\
    mov r10, 0x0E1B28661 \n\
    call WhisperMain \n\
");


#define ZwAlpcCreatePortSection NtAlpcCreatePortSection
__asm__(".intel_syntax noprefix \n\
NtAlpcCreatePortSection: \n\
    mov r10, 0x04ED3ADC1 \n\
    call WhisperMain \n\
");


#define ZwAlpcCreateResourceReserve NtAlpcCreateResourceReserve
__asm__(".intel_syntax noprefix \n\
NtAlpcCreateResourceReserve: \n\
    mov r10, 0x0FE6AE8DB \n\
    call WhisperMain \n\
");


#define ZwAlpcCreateSectionView NtAlpcCreateSectionView
__asm__(".intel_syntax noprefix \n\
NtAlpcCreateSectionView: \n\
    mov r10, 0x042F6634D \n\
    call WhisperMain \n\
");


#define ZwAlpcCreateSecurityContext NtAlpcCreateSecurityContext
__asm__(".intel_syntax noprefix \n\
NtAlpcCreateSecurityContext: \n\
    mov r10, 0x0FE67EBCE \n\
    call WhisperMain \n\
");


#define ZwAlpcDeletePortSection NtAlpcDeletePortSection
__asm__(".intel_syntax noprefix \n\
NtAlpcDeletePortSection: \n\
    mov r10, 0x0108A121F \n\
    call WhisperMain \n\
");


#define ZwAlpcDeleteResourceReserve NtAlpcDeleteResourceReserve
__asm__(".intel_syntax noprefix \n\
NtAlpcDeleteResourceReserve: \n\
    mov r10, 0x038BCC8D7 \n\
    call WhisperMain \n\
");


#define ZwAlpcDeleteSectionView NtAlpcDeleteSectionView
__asm__(".intel_syntax noprefix \n\
NtAlpcDeleteSectionView: \n\
    mov r10, 0x007AEFAC8 \n\
    call WhisperMain \n\
");


#define ZwAlpcDeleteSecurityContext NtAlpcDeleteSecurityContext
__asm__(".intel_syntax noprefix \n\
NtAlpcDeleteSecurityContext: \n\
    mov r10, 0x0DA41CFE8 \n\
    call WhisperMain \n\
");


#define ZwAlpcDisconnectPort NtAlpcDisconnectPort
__asm__(".intel_syntax noprefix \n\
NtAlpcDisconnectPort: \n\
    mov r10, 0x064F17F5E \n\
    call WhisperMain \n\
");


#define ZwAlpcImpersonateClientContainerOfPort NtAlpcImpersonateClientContainerOfPort
__asm__(".intel_syntax noprefix \n\
NtAlpcImpersonateClientContainerOfPort: \n\
    mov r10, 0x03ABF3930 \n\
    call WhisperMain \n\
");


#define ZwAlpcImpersonateClientOfPort NtAlpcImpersonateClientOfPort
__asm__(".intel_syntax noprefix \n\
NtAlpcImpersonateClientOfPort: \n\
    mov r10, 0x0E073EFE8 \n\
    call WhisperMain \n\
");


#define ZwAlpcOpenSenderProcess NtAlpcOpenSenderProcess
__asm__(".intel_syntax noprefix \n\
NtAlpcOpenSenderProcess: \n\
    mov r10, 0x0A1BEB813 \n\
    call WhisperMain \n\
");


#define ZwAlpcOpenSenderThread NtAlpcOpenSenderThread
__asm__(".intel_syntax noprefix \n\
NtAlpcOpenSenderThread: \n\
    mov r10, 0x01CBFD609 \n\
    call WhisperMain \n\
");


#define ZwAlpcQueryInformation NtAlpcQueryInformation
__asm__(".intel_syntax noprefix \n\
NtAlpcQueryInformation: \n\
    mov r10, 0x0349C283F \n\
    call WhisperMain \n\
");


#define ZwAlpcQueryInformationMessage NtAlpcQueryInformationMessage
__asm__(".intel_syntax noprefix \n\
NtAlpcQueryInformationMessage: \n\
    mov r10, 0x007BAC4E2 \n\
    call WhisperMain \n\
");


#define ZwAlpcRevokeSecurityContext NtAlpcRevokeSecurityContext
__asm__(".intel_syntax noprefix \n\
NtAlpcRevokeSecurityContext: \n\
    mov r10, 0x0D74AC2EB \n\
    call WhisperMain \n\
");


#define ZwAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort
__asm__(".intel_syntax noprefix \n\
NtAlpcSendWaitReceivePort: \n\
    mov r10, 0x026B63B3E \n\
    call WhisperMain \n\
");


#define ZwAlpcSetInformation NtAlpcSetInformation
__asm__(".intel_syntax noprefix \n\
NtAlpcSetInformation: \n\
    mov r10, 0x064C9605B \n\
    call WhisperMain \n\
");


#define ZwAreMappedFilesTheSame NtAreMappedFilesTheSame
__asm__(".intel_syntax noprefix \n\
NtAreMappedFilesTheSame: \n\
    mov r10, 0x0AF96D807 \n\
    call WhisperMain \n\
");


#define ZwAssignProcessToJobObject NtAssignProcessToJobObject
__asm__(".intel_syntax noprefix \n\
NtAssignProcessToJobObject: \n\
    mov r10, 0x00622F45F \n\
    call WhisperMain \n\
");


#define ZwAssociateWaitCompletionPacket NtAssociateWaitCompletionPacket
__asm__(".intel_syntax noprefix \n\
NtAssociateWaitCompletionPacket: \n\
    mov r10, 0x01CBA4A67 \n\
    call WhisperMain \n\
");


#define ZwCallEnclave NtCallEnclave
__asm__(".intel_syntax noprefix \n\
NtCallEnclave: \n\
    mov r10, 0x02037B507 \n\
    call WhisperMain \n\
");


#define ZwCancelIoFileEx NtCancelIoFileEx
__asm__(".intel_syntax noprefix \n\
NtCancelIoFileEx: \n\
    mov r10, 0x058BA8AE0 \n\
    call WhisperMain \n\
");


#define ZwCancelSynchronousIoFile NtCancelSynchronousIoFile
__asm__(".intel_syntax noprefix \n\
NtCancelSynchronousIoFile: \n\
    mov r10, 0x0397931E9 \n\
    call WhisperMain \n\
");


#define ZwCancelTimer2 NtCancelTimer2
__asm__(".intel_syntax noprefix \n\
NtCancelTimer2: \n\
    mov r10, 0x0D794D342 \n\
    call WhisperMain \n\
");


#define ZwCancelWaitCompletionPacket NtCancelWaitCompletionPacket
__asm__(".intel_syntax noprefix \n\
NtCancelWaitCompletionPacket: \n\
    mov r10, 0x0795C1FCE \n\
    call WhisperMain \n\
");


#define ZwCommitComplete NtCommitComplete
__asm__(".intel_syntax noprefix \n\
NtCommitComplete: \n\
    mov r10, 0x09EC04A8E \n\
    call WhisperMain \n\
");


#define ZwCommitEnlistment NtCommitEnlistment
__asm__(".intel_syntax noprefix \n\
NtCommitEnlistment: \n\
    mov r10, 0x07B258F42 \n\
    call WhisperMain \n\
");


#define ZwCommitRegistryTransaction NtCommitRegistryTransaction
__asm__(".intel_syntax noprefix \n\
NtCommitRegistryTransaction: \n\
    mov r10, 0x00AE60C77 \n\
    call WhisperMain \n\
");


#define ZwCommitTransaction NtCommitTransaction
__asm__(".intel_syntax noprefix \n\
NtCommitTransaction: \n\
    mov r10, 0x03AAF0A0D \n\
    call WhisperMain \n\
");


#define ZwCompactKeys NtCompactKeys
__asm__(".intel_syntax noprefix \n\
NtCompactKeys: \n\
    mov r10, 0x026471BD0 \n\
    call WhisperMain \n\
");


#define ZwCompareObjects NtCompareObjects
__asm__(".intel_syntax noprefix \n\
NtCompareObjects: \n\
    mov r10, 0x049D54157 \n\
    call WhisperMain \n\
");


#define ZwCompareSigningLevels NtCompareSigningLevels
__asm__(".intel_syntax noprefix \n\
NtCompareSigningLevels: \n\
    mov r10, 0x068C56852 \n\
    call WhisperMain \n\
");


#define ZwCompareTokens NtCompareTokens
__asm__(".intel_syntax noprefix \n\
NtCompareTokens: \n\
    mov r10, 0x00D94050F \n\
    call WhisperMain \n\
");


#define ZwCompleteConnectPort NtCompleteConnectPort
__asm__(".intel_syntax noprefix \n\
NtCompleteConnectPort: \n\
    mov r10, 0x030B2196C \n\
    call WhisperMain \n\
");


#define ZwCompressKey NtCompressKey
__asm__(".intel_syntax noprefix \n\
NtCompressKey: \n\
    mov r10, 0x0D0A8E717 \n\
    call WhisperMain \n\
");


#define ZwConnectPort NtConnectPort
__asm__(".intel_syntax noprefix \n\
NtConnectPort: \n\
    mov r10, 0x03EB03B22 \n\
    call WhisperMain \n\
");


#define ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
__asm__(".intel_syntax noprefix \n\
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter: \n\
    mov r10, 0x03795DD89 \n\
    call WhisperMain \n\
");


#define ZwCreateDebugObject NtCreateDebugObject
__asm__(".intel_syntax noprefix \n\
NtCreateDebugObject: \n\
    mov r10, 0x07AE3022F \n\
    call WhisperMain \n\
");


#define ZwCreateDirectoryObject NtCreateDirectoryObject
__asm__(".intel_syntax noprefix \n\
NtCreateDirectoryObject: \n\
    mov r10, 0x03AA4760B \n\
    call WhisperMain \n\
");


#define ZwCreateDirectoryObjectEx NtCreateDirectoryObjectEx
__asm__(".intel_syntax noprefix \n\
NtCreateDirectoryObjectEx: \n\
    mov r10, 0x042AEB0D4 \n\
    call WhisperMain \n\
");


#define ZwCreateEnclave NtCreateEnclave
__asm__(".intel_syntax noprefix \n\
NtCreateEnclave: \n\
    mov r10, 0x05A1F9944 \n\
    call WhisperMain \n\
");


#define ZwCreateEnlistment NtCreateEnlistment
__asm__(".intel_syntax noprefix \n\
NtCreateEnlistment: \n\
    mov r10, 0x079DC023B \n\
    call WhisperMain \n\
");


#define ZwCreateEventPair NtCreateEventPair
__asm__(".intel_syntax noprefix \n\
NtCreateEventPair: \n\
    mov r10, 0x034944A63 \n\
    call WhisperMain \n\
");


#define ZwCreateIRTimer NtCreateIRTimer
__asm__(".intel_syntax noprefix \n\
NtCreateIRTimer: \n\
    mov r10, 0x0039635D2 \n\
    call WhisperMain \n\
");


#define ZwCreateIoCompletion NtCreateIoCompletion
__asm__(".intel_syntax noprefix \n\
NtCreateIoCompletion: \n\
    mov r10, 0x09C929232 \n\
    call WhisperMain \n\
");


#define ZwCreateJobObject NtCreateJobObject
__asm__(".intel_syntax noprefix \n\
NtCreateJobObject: \n\
    mov r10, 0x02D6903F3 \n\
    call WhisperMain \n\
");


#define ZwCreateJobSet NtCreateJobSet
__asm__(".intel_syntax noprefix \n\
NtCreateJobSet: \n\
    mov r10, 0x0F3CEDF11 \n\
    call WhisperMain \n\
");


#define ZwCreateKeyTransacted NtCreateKeyTransacted
__asm__(".intel_syntax noprefix \n\
NtCreateKeyTransacted: \n\
    mov r10, 0x054BC1602 \n\
    call WhisperMain \n\
");


#define ZwCreateKeyedEvent NtCreateKeyedEvent
__asm__(".intel_syntax noprefix \n\
NtCreateKeyedEvent: \n\
    mov r10, 0x069329245 \n\
    call WhisperMain \n\
");


#define ZwCreateLowBoxToken NtCreateLowBoxToken
__asm__(".intel_syntax noprefix \n\
NtCreateLowBoxToken: \n\
    mov r10, 0x067D8535A \n\
    call WhisperMain \n\
");


#define ZwCreateMailslotFile NtCreateMailslotFile
__asm__(".intel_syntax noprefix \n\
NtCreateMailslotFile: \n\
    mov r10, 0x02EBDB48A \n\
    call WhisperMain \n\
");


#define ZwCreateMutant NtCreateMutant
__asm__(".intel_syntax noprefix \n\
NtCreateMutant: \n\
    mov r10, 0x0BE119B48 \n\
    call WhisperMain \n\
");


#define ZwCreateNamedPipeFile NtCreateNamedPipeFile
__asm__(".intel_syntax noprefix \n\
NtCreateNamedPipeFile: \n\
    mov r10, 0x096197812 \n\
    call WhisperMain \n\
");


#define ZwCreatePagingFile NtCreatePagingFile
__asm__(".intel_syntax noprefix \n\
NtCreatePagingFile: \n\
    mov r10, 0x074B2026E \n\
    call WhisperMain \n\
");


#define ZwCreatePartition NtCreatePartition
__asm__(".intel_syntax noprefix \n\
NtCreatePartition: \n\
    mov r10, 0x014825455 \n\
    call WhisperMain \n\
");


#define ZwCreatePort NtCreatePort
__asm__(".intel_syntax noprefix \n\
NtCreatePort: \n\
    mov r10, 0x01CB1E5DC \n\
    call WhisperMain \n\
");


#define ZwCreatePrivateNamespace NtCreatePrivateNamespace
__asm__(".intel_syntax noprefix \n\
NtCreatePrivateNamespace: \n\
    mov r10, 0x04E908625 \n\
    call WhisperMain \n\
");


#define ZwCreateProcess NtCreateProcess
__asm__(".intel_syntax noprefix \n\
NtCreateProcess: \n\
    mov r10, 0x05FDE4E52 \n\
    call WhisperMain \n\
");


#define ZwCreateProfile NtCreateProfile
__asm__(".intel_syntax noprefix \n\
NtCreateProfile: \n\
    mov r10, 0x000DAF080 \n\
    call WhisperMain \n\
");


#define ZwCreateProfileEx NtCreateProfileEx
__asm__(".intel_syntax noprefix \n\
NtCreateProfileEx: \n\
    mov r10, 0x0805BB2E1 \n\
    call WhisperMain \n\
");


#define ZwCreateRegistryTransaction NtCreateRegistryTransaction
__asm__(".intel_syntax noprefix \n\
NtCreateRegistryTransaction: \n\
    mov r10, 0x01E8E381B \n\
    call WhisperMain \n\
");


#define ZwCreateResourceManager NtCreateResourceManager
__asm__(".intel_syntax noprefix \n\
NtCreateResourceManager: \n\
    mov r10, 0x0103302B8 \n\
    call WhisperMain \n\
");


#define ZwCreateSemaphore NtCreateSemaphore
__asm__(".intel_syntax noprefix \n\
NtCreateSemaphore: \n\
    mov r10, 0x01D0FC3B4 \n\
    call WhisperMain \n\
");


#define ZwCreateSymbolicLinkObject NtCreateSymbolicLinkObject
__asm__(".intel_syntax noprefix \n\
NtCreateSymbolicLinkObject: \n\
    mov r10, 0x09A26E8CB \n\
    call WhisperMain \n\
");


#define ZwCreateThreadEx NtCreateThreadEx
__asm__(".intel_syntax noprefix \n\
NtCreateThreadEx: \n\
    mov r10, 0x054AA9BDD \n\
    call WhisperMain \n\
");


#define ZwCreateTimer NtCreateTimer
__asm__(".intel_syntax noprefix \n\
NtCreateTimer: \n\
    mov r10, 0x0144622FF \n\
    call WhisperMain \n\
");


#define ZwCreateTimer2 NtCreateTimer2
__asm__(".intel_syntax noprefix \n\
NtCreateTimer2: \n\
    mov r10, 0x0EB52365D \n\
    call WhisperMain \n\
");


#define ZwCreateToken NtCreateToken
__asm__(".intel_syntax noprefix \n\
NtCreateToken: \n\
    mov r10, 0x020482AD1 \n\
    call WhisperMain \n\
");


#define ZwCreateTokenEx NtCreateTokenEx
__asm__(".intel_syntax noprefix \n\
NtCreateTokenEx: \n\
    mov r10, 0x08A99CC66 \n\
    call WhisperMain \n\
");


#define ZwCreateTransaction NtCreateTransaction
__asm__(".intel_syntax noprefix \n\
NtCreateTransaction: \n\
    mov r10, 0x0168C3411 \n\
    call WhisperMain \n\
");


#define ZwCreateTransactionManager NtCreateTransactionManager
__asm__(".intel_syntax noprefix \n\
NtCreateTransactionManager: \n\
    mov r10, 0x0B22E98B3 \n\
    call WhisperMain \n\
");


#define ZwCreateUserProcess NtCreateUserProcess
__asm__(".intel_syntax noprefix \n\
NtCreateUserProcess: \n\
    mov r10, 0x065392CE4 \n\
    call WhisperMain \n\
");


#define ZwCreateWaitCompletionPacket NtCreateWaitCompletionPacket
__asm__(".intel_syntax noprefix \n\
NtCreateWaitCompletionPacket: \n\
    mov r10, 0x0393C3BA2 \n\
    call WhisperMain \n\
");


#define ZwCreateWaitablePort NtCreateWaitablePort
__asm__(".intel_syntax noprefix \n\
NtCreateWaitablePort: \n\
    mov r10, 0x020BD2726 \n\
    call WhisperMain \n\
");


#define ZwCreateWnfStateName NtCreateWnfStateName
__asm__(".intel_syntax noprefix \n\
NtCreateWnfStateName: \n\
    mov r10, 0x01CBECF89 \n\
    call WhisperMain \n\
");


#define ZwCreateWorkerFactory NtCreateWorkerFactory
__asm__(".intel_syntax noprefix \n\
NtCreateWorkerFactory: \n\
    mov r10, 0x02AA91E26 \n\
    call WhisperMain \n\
");


#define ZwDebugActiveProcess NtDebugActiveProcess
__asm__(".intel_syntax noprefix \n\
NtDebugActiveProcess: \n\
    mov r10, 0x08E248FAB \n\
    call WhisperMain \n\
");


#define ZwDebugContinue NtDebugContinue
__asm__(".intel_syntax noprefix \n\
NtDebugContinue: \n\
    mov r10, 0x096119E7C \n\
    call WhisperMain \n\
");


#define ZwDeleteAtom NtDeleteAtom
__asm__(".intel_syntax noprefix \n\
NtDeleteAtom: \n\
    mov r10, 0x0D27FF1E0 \n\
    call WhisperMain \n\
");


#define ZwDeleteBootEntry NtDeleteBootEntry
__asm__(".intel_syntax noprefix \n\
NtDeleteBootEntry: \n\
    mov r10, 0x0C99D3CE3 \n\
    call WhisperMain \n\
");


#define ZwDeleteDriverEntry NtDeleteDriverEntry
__asm__(".intel_syntax noprefix \n\
NtDeleteDriverEntry: \n\
    mov r10, 0x0DF9315D0 \n\
    call WhisperMain \n\
");


#define ZwDeleteFile NtDeleteFile
__asm__(".intel_syntax noprefix \n\
NtDeleteFile: \n\
    mov r10, 0x0E278ECDC \n\
    call WhisperMain \n\
");


#define ZwDeleteKey NtDeleteKey
__asm__(".intel_syntax noprefix \n\
NtDeleteKey: \n\
    mov r10, 0x01FAB3208 \n\
    call WhisperMain \n\
");


#define ZwDeleteObjectAuditAlarm NtDeleteObjectAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtDeleteObjectAuditAlarm: \n\
    mov r10, 0x01897120A \n\
    call WhisperMain \n\
");


#define ZwDeletePrivateNamespace NtDeletePrivateNamespace
__asm__(".intel_syntax noprefix \n\
NtDeletePrivateNamespace: \n\
    mov r10, 0x01EB55799 \n\
    call WhisperMain \n\
");


#define ZwDeleteValueKey NtDeleteValueKey
__asm__(".intel_syntax noprefix \n\
NtDeleteValueKey: \n\
    mov r10, 0x0A79A9224 \n\
    call WhisperMain \n\
");


#define ZwDeleteWnfStateData NtDeleteWnfStateData
__asm__(".intel_syntax noprefix \n\
NtDeleteWnfStateData: \n\
    mov r10, 0x076BC4014 \n\
    call WhisperMain \n\
");


#define ZwDeleteWnfStateName NtDeleteWnfStateName
__asm__(".intel_syntax noprefix \n\
NtDeleteWnfStateName: \n\
    mov r10, 0x00CC22507 \n\
    call WhisperMain \n\
");


#define ZwDisableLastKnownGood NtDisableLastKnownGood
__asm__(".intel_syntax noprefix \n\
NtDisableLastKnownGood: \n\
    mov r10, 0x0F82FF685 \n\
    call WhisperMain \n\
");


#define ZwDisplayString NtDisplayString
__asm__(".intel_syntax noprefix \n\
NtDisplayString: \n\
    mov r10, 0x01E8E2A1E \n\
    call WhisperMain \n\
");


#define ZwDrawText NtDrawText
__asm__(".intel_syntax noprefix \n\
NtDrawText: \n\
    mov r10, 0x0D24BD7C2 \n\
    call WhisperMain \n\
");


#define ZwEnableLastKnownGood NtEnableLastKnownGood
__asm__(".intel_syntax noprefix \n\
NtEnableLastKnownGood: \n\
    mov r10, 0x09DCEAD19 \n\
    call WhisperMain \n\
");


#define ZwEnumerateBootEntries NtEnumerateBootEntries
__asm__(".intel_syntax noprefix \n\
NtEnumerateBootEntries: \n\
    mov r10, 0x04C914109 \n\
    call WhisperMain \n\
");


#define ZwEnumerateDriverEntries NtEnumerateDriverEntries
__asm__(".intel_syntax noprefix \n\
NtEnumerateDriverEntries: \n\
    mov r10, 0x034844D6F \n\
    call WhisperMain \n\
");


#define ZwEnumerateSystemEnvironmentValuesEx NtEnumerateSystemEnvironmentValuesEx
__asm__(".intel_syntax noprefix \n\
NtEnumerateSystemEnvironmentValuesEx: \n\
    mov r10, 0x07FD24267 \n\
    call WhisperMain \n\
");


#define ZwEnumerateTransactionObject NtEnumerateTransactionObject
__asm__(".intel_syntax noprefix \n\
NtEnumerateTransactionObject: \n\
    mov r10, 0x06AB56A29 \n\
    call WhisperMain \n\
");


#define ZwExtendSection NtExtendSection
__asm__(".intel_syntax noprefix \n\
NtExtendSection: \n\
    mov r10, 0x038A81E21 \n\
    call WhisperMain \n\
");


#define ZwFilterBootOption NtFilterBootOption
__asm__(".intel_syntax noprefix \n\
NtFilterBootOption: \n\
    mov r10, 0x03A92D781 \n\
    call WhisperMain \n\
");


#define ZwFilterToken NtFilterToken
__asm__(".intel_syntax noprefix \n\
NtFilterToken: \n\
    mov r10, 0x0E55CD3D8 \n\
    call WhisperMain \n\
");


#define ZwFilterTokenEx NtFilterTokenEx
__asm__(".intel_syntax noprefix \n\
NtFilterTokenEx: \n\
    mov r10, 0x00484F1F9 \n\
    call WhisperMain \n\
");


#define ZwFlushBuffersFileEx NtFlushBuffersFileEx
__asm__(".intel_syntax noprefix \n\
NtFlushBuffersFileEx: \n\
    mov r10, 0x00B9845AE \n\
    call WhisperMain \n\
");


#define ZwFlushInstallUILanguage NtFlushInstallUILanguage
__asm__(".intel_syntax noprefix \n\
NtFlushInstallUILanguage: \n\
    mov r10, 0x0F557C2CE \n\
    call WhisperMain \n\
");


#define ZwFlushInstructionCache NtFlushInstructionCache
__asm__(".intel_syntax noprefix \n\
NtFlushInstructionCache: \n\
    mov r10, 0x0693F9567 \n\
    call WhisperMain \n\
");


#define ZwFlushKey NtFlushKey
__asm__(".intel_syntax noprefix \n\
NtFlushKey: \n\
    mov r10, 0x0D461E3DF \n\
    call WhisperMain \n\
");


#define ZwFlushProcessWriteBuffers NtFlushProcessWriteBuffers
__asm__(".intel_syntax noprefix \n\
NtFlushProcessWriteBuffers: \n\
    mov r10, 0x07EBC7E2C \n\
    call WhisperMain \n\
");


#define ZwFlushVirtualMemory NtFlushVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtFlushVirtualMemory: \n\
    mov r10, 0x0B31C89AF \n\
    call WhisperMain \n\
");


#define ZwFlushWriteBuffer NtFlushWriteBuffer
__asm__(".intel_syntax noprefix \n\
NtFlushWriteBuffer: \n\
    mov r10, 0x06BC0429B \n\
    call WhisperMain \n\
");


#define ZwFreeUserPhysicalPages NtFreeUserPhysicalPages
__asm__(".intel_syntax noprefix \n\
NtFreeUserPhysicalPages: \n\
    mov r10, 0x011BC2A12 \n\
    call WhisperMain \n\
");


#define ZwFreezeRegistry NtFreezeRegistry
__asm__(".intel_syntax noprefix \n\
NtFreezeRegistry: \n\
    mov r10, 0x026452CC5 \n\
    call WhisperMain \n\
");


#define ZwFreezeTransactions NtFreezeTransactions
__asm__(".intel_syntax noprefix \n\
NtFreezeTransactions: \n\
    mov r10, 0x013CB00AD \n\
    call WhisperMain \n\
");


#define ZwGetCachedSigningLevel NtGetCachedSigningLevel
__asm__(".intel_syntax noprefix \n\
NtGetCachedSigningLevel: \n\
    mov r10, 0x0B28BB815 \n\
    call WhisperMain \n\
");


#define ZwGetCompleteWnfStateSubscription NtGetCompleteWnfStateSubscription
__asm__(".intel_syntax noprefix \n\
NtGetCompleteWnfStateSubscription: \n\
    mov r10, 0x044CB0A13 \n\
    call WhisperMain \n\
");


#define ZwGetContextThread NtGetContextThread
__asm__(".intel_syntax noprefix \n\
NtGetContextThread: \n\
    mov r10, 0x06B4E279E \n\
    call WhisperMain \n\
");


#define ZwGetCurrentProcessorNumber NtGetCurrentProcessorNumber
__asm__(".intel_syntax noprefix \n\
NtGetCurrentProcessorNumber: \n\
    mov r10, 0x006937878 \n\
    call WhisperMain \n\
");


#define ZwGetCurrentProcessorNumberEx NtGetCurrentProcessorNumberEx
__asm__(".intel_syntax noprefix \n\
NtGetCurrentProcessorNumberEx: \n\
    mov r10, 0x084EAA254 \n\
    call WhisperMain \n\
");


#define ZwGetDevicePowerState NtGetDevicePowerState
__asm__(".intel_syntax noprefix \n\
NtGetDevicePowerState: \n\
    mov r10, 0x0B49BA434 \n\
    call WhisperMain \n\
");


#define ZwGetMUIRegistryInfo NtGetMUIRegistryInfo
__asm__(".intel_syntax noprefix \n\
NtGetMUIRegistryInfo: \n\
    mov r10, 0x084B7B211 \n\
    call WhisperMain \n\
");


#define ZwGetNextProcess NtGetNextProcess
__asm__(".intel_syntax noprefix \n\
NtGetNextProcess: \n\
    mov r10, 0x01B9E1E0E \n\
    call WhisperMain \n\
");


#define ZwGetNextThread NtGetNextThread
__asm__(".intel_syntax noprefix \n\
NtGetNextThread: \n\
    mov r10, 0x0EE4B2CED \n\
    call WhisperMain \n\
");


#define ZwGetNlsSectionPtr NtGetNlsSectionPtr
__asm__(".intel_syntax noprefix \n\
NtGetNlsSectionPtr: \n\
    mov r10, 0x02B12C80E \n\
    call WhisperMain \n\
");


#define ZwGetNotificationResourceManager NtGetNotificationResourceManager
__asm__(".intel_syntax noprefix \n\
NtGetNotificationResourceManager: \n\
    mov r10, 0x0823CAA87 \n\
    call WhisperMain \n\
");


#define ZwGetWriteWatch NtGetWriteWatch
__asm__(".intel_syntax noprefix \n\
NtGetWriteWatch: \n\
    mov r10, 0x0105E2CDA \n\
    call WhisperMain \n\
");


#define ZwImpersonateAnonymousToken NtImpersonateAnonymousToken
__asm__(".intel_syntax noprefix \n\
NtImpersonateAnonymousToken: \n\
    mov r10, 0x04550AA4A \n\
    call WhisperMain \n\
");


#define ZwImpersonateThread NtImpersonateThread
__asm__(".intel_syntax noprefix \n\
NtImpersonateThread: \n\
    mov r10, 0x0B000BAAE \n\
    call WhisperMain \n\
");


#define ZwInitializeEnclave NtInitializeEnclave
__asm__(".intel_syntax noprefix \n\
NtInitializeEnclave: \n\
    mov r10, 0x02C93C098 \n\
    call WhisperMain \n\
");


#define ZwInitializeNlsFiles NtInitializeNlsFiles
__asm__(".intel_syntax noprefix \n\
NtInitializeNlsFiles: \n\
    mov r10, 0x06CECA3B6 \n\
    call WhisperMain \n\
");


#define ZwInitializeRegistry NtInitializeRegistry
__asm__(".intel_syntax noprefix \n\
NtInitializeRegistry: \n\
    mov r10, 0x0BC533055 \n\
    call WhisperMain \n\
");


#define ZwInitiatePowerAction NtInitiatePowerAction
__asm__(".intel_syntax noprefix \n\
NtInitiatePowerAction: \n\
    mov r10, 0x0CB578F84 \n\
    call WhisperMain \n\
");


#define ZwIsSystemResumeAutomatic NtIsSystemResumeAutomatic
__asm__(".intel_syntax noprefix \n\
NtIsSystemResumeAutomatic: \n\
    mov r10, 0x00440C162 \n\
    call WhisperMain \n\
");


#define ZwIsUILanguageComitted NtIsUILanguageComitted
__asm__(".intel_syntax noprefix \n\
NtIsUILanguageComitted: \n\
    mov r10, 0x027AA3515 \n\
    call WhisperMain \n\
");


#define ZwListenPort NtListenPort
__asm__(".intel_syntax noprefix \n\
NtListenPort: \n\
    mov r10, 0x0E173E0FD \n\
    call WhisperMain \n\
");


#define ZwLoadDriver NtLoadDriver
__asm__(".intel_syntax noprefix \n\
NtLoadDriver: \n\
    mov r10, 0x012B81A26 \n\
    call WhisperMain \n\
");


#define ZwLoadEnclaveData NtLoadEnclaveData
__asm__(".intel_syntax noprefix \n\
NtLoadEnclaveData: \n\
    mov r10, 0x0849AD429 \n\
    call WhisperMain \n\
");


#define ZwLoadHotPatch NtLoadHotPatch
__asm__(".intel_syntax noprefix \n\
NtLoadHotPatch: \n\
    mov r10, 0x0ECA229FE \n\
    call WhisperMain \n\
");


#define ZwLoadKey NtLoadKey
__asm__(".intel_syntax noprefix \n\
NtLoadKey: \n\
    mov r10, 0x0083A69A3 \n\
    call WhisperMain \n\
");


#define ZwLoadKey2 NtLoadKey2
__asm__(".intel_syntax noprefix \n\
NtLoadKey2: \n\
    mov r10, 0x0AB3221EE \n\
    call WhisperMain \n\
");


#define ZwLoadKeyEx NtLoadKeyEx
__asm__(".intel_syntax noprefix \n\
NtLoadKeyEx: \n\
    mov r10, 0x07399B624 \n\
    call WhisperMain \n\
");


#define ZwLockFile NtLockFile
__asm__(".intel_syntax noprefix \n\
NtLockFile: \n\
    mov r10, 0x03A3D365A \n\
    call WhisperMain \n\
");


#define ZwLockProductActivationKeys NtLockProductActivationKeys
__asm__(".intel_syntax noprefix \n\
NtLockProductActivationKeys: \n\
    mov r10, 0x04F3248A0 \n\
    call WhisperMain \n\
");


#define ZwLockRegistryKey NtLockRegistryKey
__asm__(".intel_syntax noprefix \n\
NtLockRegistryKey: \n\
    mov r10, 0x0DEABF13D \n\
    call WhisperMain \n\
");


#define ZwLockVirtualMemory NtLockVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtLockVirtualMemory: \n\
    mov r10, 0x00794EEFB \n\
    call WhisperMain \n\
");


#define ZwMakePermanentObject NtMakePermanentObject
__asm__(".intel_syntax noprefix \n\
NtMakePermanentObject: \n\
    mov r10, 0x0A13ECFE4 \n\
    call WhisperMain \n\
");


#define ZwMakeTemporaryObject NtMakeTemporaryObject
__asm__(".intel_syntax noprefix \n\
NtMakeTemporaryObject: \n\
    mov r10, 0x01E3D74A2 \n\
    call WhisperMain \n\
");


#define ZwManagePartition NtManagePartition
__asm__(".intel_syntax noprefix \n\
NtManagePartition: \n\
    mov r10, 0x00AE16A33 \n\
    call WhisperMain \n\
");


#define ZwMapCMFModule NtMapCMFModule
__asm__(".intel_syntax noprefix \n\
NtMapCMFModule: \n\
    mov r10, 0x0169B1AFC \n\
    call WhisperMain \n\
");


#define ZwMapUserPhysicalPages NtMapUserPhysicalPages
__asm__(".intel_syntax noprefix \n\
NtMapUserPhysicalPages: \n\
    mov r10, 0x029B5721E \n\
    call WhisperMain \n\
");


#define ZwMapViewOfSectionEx NtMapViewOfSectionEx
__asm__(".intel_syntax noprefix \n\
NtMapViewOfSectionEx: \n\
    mov r10, 0x0365CF80A \n\
    call WhisperMain \n\
");


#define ZwModifyBootEntry NtModifyBootEntry
__asm__(".intel_syntax noprefix \n\
NtModifyBootEntry: \n\
    mov r10, 0x0099AFCE1 \n\
    call WhisperMain \n\
");


#define ZwModifyDriverEntry NtModifyDriverEntry
__asm__(".intel_syntax noprefix \n\
NtModifyDriverEntry: \n\
    mov r10, 0x021C8CD98 \n\
    call WhisperMain \n\
");


#define ZwNotifyChangeDirectoryFile NtNotifyChangeDirectoryFile
__asm__(".intel_syntax noprefix \n\
NtNotifyChangeDirectoryFile: \n\
    mov r10, 0x0AA3A816E \n\
    call WhisperMain \n\
");


#define ZwNotifyChangeDirectoryFileEx NtNotifyChangeDirectoryFileEx
__asm__(".intel_syntax noprefix \n\
NtNotifyChangeDirectoryFileEx: \n\
    mov r10, 0x08B54FFA8 \n\
    call WhisperMain \n\
");


#define ZwNotifyChangeKey NtNotifyChangeKey
__asm__(".intel_syntax noprefix \n\
NtNotifyChangeKey: \n\
    mov r10, 0x0F1FBD3A0 \n\
    call WhisperMain \n\
");


#define ZwNotifyChangeMultipleKeys NtNotifyChangeMultipleKeys
__asm__(".intel_syntax noprefix \n\
NtNotifyChangeMultipleKeys: \n\
    mov r10, 0x065BE7236 \n\
    call WhisperMain \n\
");


#define ZwNotifyChangeSession NtNotifyChangeSession
__asm__(".intel_syntax noprefix \n\
NtNotifyChangeSession: \n\
    mov r10, 0x001890314 \n\
    call WhisperMain \n\
");


#define ZwOpenEnlistment NtOpenEnlistment
__asm__(".intel_syntax noprefix \n\
NtOpenEnlistment: \n\
    mov r10, 0x05BD55E63 \n\
    call WhisperMain \n\
");


#define ZwOpenEventPair NtOpenEventPair
__asm__(".intel_syntax noprefix \n\
NtOpenEventPair: \n\
    mov r10, 0x020944861 \n\
    call WhisperMain \n\
");


#define ZwOpenIoCompletion NtOpenIoCompletion
__asm__(".intel_syntax noprefix \n\
NtOpenIoCompletion: \n\
    mov r10, 0x07067F071 \n\
    call WhisperMain \n\
");


#define ZwOpenJobObject NtOpenJobObject
__asm__(".intel_syntax noprefix \n\
NtOpenJobObject: \n\
    mov r10, 0x0F341013F \n\
    call WhisperMain \n\
");


#define ZwOpenKeyEx NtOpenKeyEx
__asm__(".intel_syntax noprefix \n\
NtOpenKeyEx: \n\
    mov r10, 0x00F99C3DC \n\
    call WhisperMain \n\
");


#define ZwOpenKeyTransacted NtOpenKeyTransacted
__asm__(".intel_syntax noprefix \n\
NtOpenKeyTransacted: \n\
    mov r10, 0x0104416DE \n\
    call WhisperMain \n\
");


#define ZwOpenKeyTransactedEx NtOpenKeyTransactedEx
__asm__(".intel_syntax noprefix \n\
NtOpenKeyTransactedEx: \n\
    mov r10, 0x0889ABA21 \n\
    call WhisperMain \n\
");


#define ZwOpenKeyedEvent NtOpenKeyedEvent
__asm__(".intel_syntax noprefix \n\
NtOpenKeyedEvent: \n\
    mov r10, 0x0E87FEBE8 \n\
    call WhisperMain \n\
");


#define ZwOpenMutant NtOpenMutant
__asm__(".intel_syntax noprefix \n\
NtOpenMutant: \n\
    mov r10, 0x0B22DF5FE \n\
    call WhisperMain \n\
");


#define ZwOpenObjectAuditAlarm NtOpenObjectAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtOpenObjectAuditAlarm: \n\
    mov r10, 0x02AAD0E7C \n\
    call WhisperMain \n\
");


#define ZwOpenPartition NtOpenPartition
__asm__(".intel_syntax noprefix \n\
NtOpenPartition: \n\
    mov r10, 0x0108DD0DF \n\
    call WhisperMain \n\
");


#define ZwOpenPrivateNamespace NtOpenPrivateNamespace
__asm__(".intel_syntax noprefix \n\
NtOpenPrivateNamespace: \n\
    mov r10, 0x0785F07BD \n\
    call WhisperMain \n\
");


#define ZwOpenProcessToken NtOpenProcessToken
__asm__(".intel_syntax noprefix \n\
NtOpenProcessToken: \n\
    mov r10, 0x0E75BFBEA \n\
    call WhisperMain \n\
");


#define ZwOpenRegistryTransaction NtOpenRegistryTransaction
__asm__(".intel_syntax noprefix \n\
NtOpenRegistryTransaction: \n\
    mov r10, 0x09CC47B51 \n\
    call WhisperMain \n\
");


#define ZwOpenResourceManager NtOpenResourceManager
__asm__(".intel_syntax noprefix \n\
NtOpenResourceManager: \n\
    mov r10, 0x0F9512419 \n\
    call WhisperMain \n\
");


#define ZwOpenSemaphore NtOpenSemaphore
__asm__(".intel_syntax noprefix \n\
NtOpenSemaphore: \n\
    mov r10, 0x09306CBBB \n\
    call WhisperMain \n\
");


#define ZwOpenSession NtOpenSession
__asm__(".intel_syntax noprefix \n\
NtOpenSession: \n\
    mov r10, 0x0D2053455 \n\
    call WhisperMain \n\
");


#define ZwOpenSymbolicLinkObject NtOpenSymbolicLinkObject
__asm__(".intel_syntax noprefix \n\
NtOpenSymbolicLinkObject: \n\
    mov r10, 0x00A943819 \n\
    call WhisperMain \n\
");


#define ZwOpenThread NtOpenThread
__asm__(".intel_syntax noprefix \n\
NtOpenThread: \n\
    mov r10, 0x0183F5496 \n\
    call WhisperMain \n\
");


#define ZwOpenTimer NtOpenTimer
__asm__(".intel_syntax noprefix \n\
NtOpenTimer: \n\
    mov r10, 0x00B189804 \n\
    call WhisperMain \n\
");


#define ZwOpenTransaction NtOpenTransaction
__asm__(".intel_syntax noprefix \n\
NtOpenTransaction: \n\
    mov r10, 0x09C089C9B \n\
    call WhisperMain \n\
");


#define ZwOpenTransactionManager NtOpenTransactionManager
__asm__(".intel_syntax noprefix \n\
NtOpenTransactionManager: \n\
    mov r10, 0x005E791C6 \n\
    call WhisperMain \n\
");


#define ZwPlugPlayControl NtPlugPlayControl
__asm__(".intel_syntax noprefix \n\
NtPlugPlayControl: \n\
    mov r10, 0x0C6693A38 \n\
    call WhisperMain \n\
");


#define ZwPrePrepareComplete NtPrePrepareComplete
__asm__(".intel_syntax noprefix \n\
NtPrePrepareComplete: \n\
    mov r10, 0x0089003FE \n\
    call WhisperMain \n\
");


#define ZwPrePrepareEnlistment NtPrePrepareEnlistment
__asm__(".intel_syntax noprefix \n\
NtPrePrepareEnlistment: \n\
    mov r10, 0x0F9A71DCC \n\
    call WhisperMain \n\
");


#define ZwPrepareComplete NtPrepareComplete
__asm__(".intel_syntax noprefix \n\
NtPrepareComplete: \n\
    mov r10, 0x004D057EE \n\
    call WhisperMain \n\
");


#define ZwPrepareEnlistment NtPrepareEnlistment
__asm__(".intel_syntax noprefix \n\
NtPrepareEnlistment: \n\
    mov r10, 0x0D9469E8D \n\
    call WhisperMain \n\
");


#define ZwPrivilegeCheck NtPrivilegeCheck
__asm__(".intel_syntax noprefix \n\
NtPrivilegeCheck: \n\
    mov r10, 0x028950FC5 \n\
    call WhisperMain \n\
");


#define ZwPrivilegeObjectAuditAlarm NtPrivilegeObjectAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtPrivilegeObjectAuditAlarm: \n\
    mov r10, 0x0E12EDD61 \n\
    call WhisperMain \n\
");


#define ZwPrivilegedServiceAuditAlarm NtPrivilegedServiceAuditAlarm
__asm__(".intel_syntax noprefix \n\
NtPrivilegedServiceAuditAlarm: \n\
    mov r10, 0x012B41622 \n\
    call WhisperMain \n\
");


#define ZwPropagationComplete NtPropagationComplete
__asm__(".intel_syntax noprefix \n\
NtPropagationComplete: \n\
    mov r10, 0x00E913E3A \n\
    call WhisperMain \n\
");


#define ZwPropagationFailed NtPropagationFailed
__asm__(".intel_syntax noprefix \n\
NtPropagationFailed: \n\
    mov r10, 0x04ED9AF84 \n\
    call WhisperMain \n\
");


#define ZwPulseEvent NtPulseEvent
__asm__(".intel_syntax noprefix \n\
NtPulseEvent: \n\
    mov r10, 0x0000A1B9D \n\
    call WhisperMain \n\
");


#define ZwQueryAuxiliaryCounterFrequency NtQueryAuxiliaryCounterFrequency
__asm__(".intel_syntax noprefix \n\
NtQueryAuxiliaryCounterFrequency: \n\
    mov r10, 0x0EAD9F64C \n\
    call WhisperMain \n\
");


#define ZwQueryBootEntryOrder NtQueryBootEntryOrder
__asm__(".intel_syntax noprefix \n\
NtQueryBootEntryOrder: \n\
    mov r10, 0x0F7EEFB75 \n\
    call WhisperMain \n\
");


#define ZwQueryBootOptions NtQueryBootOptions
__asm__(".intel_syntax noprefix \n\
NtQueryBootOptions: \n\
    mov r10, 0x0178D1F1B \n\
    call WhisperMain \n\
");


#define ZwQueryDebugFilterState NtQueryDebugFilterState
__asm__(".intel_syntax noprefix \n\
NtQueryDebugFilterState: \n\
    mov r10, 0x074CA7E6A \n\
    call WhisperMain \n\
");


#define ZwQueryDirectoryFileEx NtQueryDirectoryFileEx
__asm__(".intel_syntax noprefix \n\
NtQueryDirectoryFileEx: \n\
    mov r10, 0x0C8530A69 \n\
    call WhisperMain \n\
");


#define ZwQueryDirectoryObject NtQueryDirectoryObject
__asm__(".intel_syntax noprefix \n\
NtQueryDirectoryObject: \n\
    mov r10, 0x0E65ACF07 \n\
    call WhisperMain \n\
");


#define ZwQueryDriverEntryOrder NtQueryDriverEntryOrder
__asm__(".intel_syntax noprefix \n\
NtQueryDriverEntryOrder: \n\
    mov r10, 0x013461DDB \n\
    call WhisperMain \n\
");


#define ZwQueryEaFile NtQueryEaFile
__asm__(".intel_syntax noprefix \n\
NtQueryEaFile: \n\
    mov r10, 0x0E4A4944F \n\
    call WhisperMain \n\
");


#define ZwQueryFullAttributesFile NtQueryFullAttributesFile
__asm__(".intel_syntax noprefix \n\
NtQueryFullAttributesFile: \n\
    mov r10, 0x0C6CDC662 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationAtom NtQueryInformationAtom
__asm__(".intel_syntax noprefix \n\
NtQueryInformationAtom: \n\
    mov r10, 0x09B07BA93 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationByName NtQueryInformationByName
__asm__(".intel_syntax noprefix \n\
NtQueryInformationByName: \n\
    mov r10, 0x0A80AAF91 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationEnlistment NtQueryInformationEnlistment
__asm__(".intel_syntax noprefix \n\
NtQueryInformationEnlistment: \n\
    mov r10, 0x02FB12E23 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationJobObject NtQueryInformationJobObject
__asm__(".intel_syntax noprefix \n\
NtQueryInformationJobObject: \n\
    mov r10, 0x007A5C2EB \n\
    call WhisperMain \n\
");


#define ZwQueryInformationPort NtQueryInformationPort
__asm__(".intel_syntax noprefix \n\
NtQueryInformationPort: \n\
    mov r10, 0x0A73AA8A9 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationResourceManager NtQueryInformationResourceManager
__asm__(".intel_syntax noprefix \n\
NtQueryInformationResourceManager: \n\
    mov r10, 0x007B6EEEE \n\
    call WhisperMain \n\
");


#define ZwQueryInformationTransaction NtQueryInformationTransaction
__asm__(".intel_syntax noprefix \n\
NtQueryInformationTransaction: \n\
    mov r10, 0x002ED227F \n\
    call WhisperMain \n\
");


#define ZwQueryInformationTransactionManager NtQueryInformationTransactionManager
__asm__(".intel_syntax noprefix \n\
NtQueryInformationTransactionManager: \n\
    mov r10, 0x0B32C9DB0 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationWorkerFactory NtQueryInformationWorkerFactory
__asm__(".intel_syntax noprefix \n\
NtQueryInformationWorkerFactory: \n\
    mov r10, 0x0CC9A2E03 \n\
    call WhisperMain \n\
");


#define ZwQueryInstallUILanguage NtQueryInstallUILanguage
__asm__(".intel_syntax noprefix \n\
NtQueryInstallUILanguage: \n\
    mov r10, 0x04FC9365A \n\
    call WhisperMain \n\
");


#define ZwQueryIntervalProfile NtQueryIntervalProfile
__asm__(".intel_syntax noprefix \n\
NtQueryIntervalProfile: \n\
    mov r10, 0x0D73B26AF \n\
    call WhisperMain \n\
");


#define ZwQueryIoCompletion NtQueryIoCompletion
__asm__(".intel_syntax noprefix \n\
NtQueryIoCompletion: \n\
    mov r10, 0x05ED55E47 \n\
    call WhisperMain \n\
");


#define ZwQueryLicenseValue NtQueryLicenseValue
__asm__(".intel_syntax noprefix \n\
NtQueryLicenseValue: \n\
    mov r10, 0x0D4433CCC \n\
    call WhisperMain \n\
");


#define ZwQueryMultipleValueKey NtQueryMultipleValueKey
__asm__(".intel_syntax noprefix \n\
NtQueryMultipleValueKey: \n\
    mov r10, 0x0825AF1A0 \n\
    call WhisperMain \n\
");


#define ZwQueryMutant NtQueryMutant
__asm__(".intel_syntax noprefix \n\
NtQueryMutant: \n\
    mov r10, 0x0DE19F380 \n\
    call WhisperMain \n\
");


#define ZwQueryOpenSubKeys NtQueryOpenSubKeys
__asm__(".intel_syntax noprefix \n\
NtQueryOpenSubKeys: \n\
    mov r10, 0x00DB3606A \n\
    call WhisperMain \n\
");


#define ZwQueryOpenSubKeysEx NtQueryOpenSubKeysEx
__asm__(".intel_syntax noprefix \n\
NtQueryOpenSubKeysEx: \n\
    mov r10, 0x061DAB182 \n\
    call WhisperMain \n\
");


#define ZwQueryPortInformationProcess NtQueryPortInformationProcess
__asm__(".intel_syntax noprefix \n\
NtQueryPortInformationProcess: \n\
    mov r10, 0x069306CA8 \n\
    call WhisperMain \n\
");


#define ZwQueryQuotaInformationFile NtQueryQuotaInformationFile
__asm__(".intel_syntax noprefix \n\
NtQueryQuotaInformationFile: \n\
    mov r10, 0x0E2B83781 \n\
    call WhisperMain \n\
");


#define ZwQuerySecurityAttributesToken NtQuerySecurityAttributesToken
__asm__(".intel_syntax noprefix \n\
NtQuerySecurityAttributesToken: \n\
    mov r10, 0x07D27A48C \n\
    call WhisperMain \n\
");


#define ZwQuerySecurityObject NtQuerySecurityObject
__asm__(".intel_syntax noprefix \n\
NtQuerySecurityObject: \n\
    mov r10, 0x013BCE0C3 \n\
    call WhisperMain \n\
");


#define ZwQuerySecurityPolicy NtQuerySecurityPolicy
__asm__(".intel_syntax noprefix \n\
NtQuerySecurityPolicy: \n\
    mov r10, 0x005AAE1D7 \n\
    call WhisperMain \n\
");


#define ZwQuerySemaphore NtQuerySemaphore
__asm__(".intel_syntax noprefix \n\
NtQuerySemaphore: \n\
    mov r10, 0x03AAA6416 \n\
    call WhisperMain \n\
");


#define ZwQuerySymbolicLinkObject NtQuerySymbolicLinkObject
__asm__(".intel_syntax noprefix \n\
NtQuerySymbolicLinkObject: \n\
    mov r10, 0x01702E100 \n\
    call WhisperMain \n\
");


#define ZwQuerySystemEnvironmentValue NtQuerySystemEnvironmentValue
__asm__(".intel_syntax noprefix \n\
NtQuerySystemEnvironmentValue: \n\
    mov r10, 0x0CA9129DA \n\
    call WhisperMain \n\
");


#define ZwQuerySystemEnvironmentValueEx NtQuerySystemEnvironmentValueEx
__asm__(".intel_syntax noprefix \n\
NtQuerySystemEnvironmentValueEx: \n\
    mov r10, 0x0534A0796 \n\
    call WhisperMain \n\
");


#define ZwQuerySystemInformationEx NtQuerySystemInformationEx
__asm__(".intel_syntax noprefix \n\
NtQuerySystemInformationEx: \n\
    mov r10, 0x09694C44E \n\
    call WhisperMain \n\
");


#define ZwQueryTimerResolution NtQueryTimerResolution
__asm__(".intel_syntax noprefix \n\
NtQueryTimerResolution: \n\
    mov r10, 0x0C24DE4D9 \n\
    call WhisperMain \n\
");


#define ZwQueryWnfStateData NtQueryWnfStateData
__asm__(".intel_syntax noprefix \n\
NtQueryWnfStateData: \n\
    mov r10, 0x0A3039595 \n\
    call WhisperMain \n\
");


#define ZwQueryWnfStateNameInformation NtQueryWnfStateNameInformation
__asm__(".intel_syntax noprefix \n\
NtQueryWnfStateNameInformation: \n\
    mov r10, 0x0FAEB18E7 \n\
    call WhisperMain \n\
");


#define ZwQueueApcThreadEx NtQueueApcThreadEx
__asm__(".intel_syntax noprefix \n\
NtQueueApcThreadEx: \n\
    mov r10, 0x0FCACFE16 \n\
    call WhisperMain \n\
");


#define ZwRaiseException NtRaiseException
__asm__(".intel_syntax noprefix \n\
NtRaiseException: \n\
    mov r10, 0x03F6E1A3D \n\
    call WhisperMain \n\
");


#define ZwRaiseHardError NtRaiseHardError
__asm__(".intel_syntax noprefix \n\
NtRaiseHardError: \n\
    mov r10, 0x0CF5CD1CD \n\
    call WhisperMain \n\
");


#define ZwReadOnlyEnlistment NtReadOnlyEnlistment
__asm__(".intel_syntax noprefix \n\
NtReadOnlyEnlistment: \n\
    mov r10, 0x09236B7A4 \n\
    call WhisperMain \n\
");


#define ZwRecoverEnlistment NtRecoverEnlistment
__asm__(".intel_syntax noprefix \n\
NtRecoverEnlistment: \n\
    mov r10, 0x0C8530818 \n\
    call WhisperMain \n\
");


#define ZwRecoverResourceManager NtRecoverResourceManager
__asm__(".intel_syntax noprefix \n\
NtRecoverResourceManager: \n\
    mov r10, 0x0605F52FC \n\
    call WhisperMain \n\
");


#define ZwRecoverTransactionManager NtRecoverTransactionManager
__asm__(".intel_syntax noprefix \n\
NtRecoverTransactionManager: \n\
    mov r10, 0x006379837 \n\
    call WhisperMain \n\
");


#define ZwRegisterProtocolAddressInformation NtRegisterProtocolAddressInformation
__asm__(".intel_syntax noprefix \n\
NtRegisterProtocolAddressInformation: \n\
    mov r10, 0x0049326C7 \n\
    call WhisperMain \n\
");


#define ZwRegisterThreadTerminatePort NtRegisterThreadTerminatePort
__asm__(".intel_syntax noprefix \n\
NtRegisterThreadTerminatePort: \n\
    mov r10, 0x0EE76DE3A \n\
    call WhisperMain \n\
");


#define ZwReleaseKeyedEvent NtReleaseKeyedEvent
__asm__(".intel_syntax noprefix \n\
NtReleaseKeyedEvent: \n\
    mov r10, 0x0DB88FCD3 \n\
    call WhisperMain \n\
");


#define ZwReleaseWorkerFactoryWorker NtReleaseWorkerFactoryWorker
__asm__(".intel_syntax noprefix \n\
NtReleaseWorkerFactoryWorker: \n\
    mov r10, 0x03E9FE8BB \n\
    call WhisperMain \n\
");


#define ZwRemoveIoCompletionEx NtRemoveIoCompletionEx
__asm__(".intel_syntax noprefix \n\
NtRemoveIoCompletionEx: \n\
    mov r10, 0x06496A2E8 \n\
    call WhisperMain \n\
");


#define ZwRemoveProcessDebug NtRemoveProcessDebug
__asm__(".intel_syntax noprefix \n\
NtRemoveProcessDebug: \n\
    mov r10, 0x0CA5FCBF4 \n\
    call WhisperMain \n\
");


#define ZwRenameKey NtRenameKey
__asm__(".intel_syntax noprefix \n\
NtRenameKey: \n\
    mov r10, 0x0E9DF04AC \n\
    call WhisperMain \n\
");


#define ZwRenameTransactionManager NtRenameTransactionManager
__asm__(".intel_syntax noprefix \n\
NtRenameTransactionManager: \n\
    mov r10, 0x005B75116 \n\
    call WhisperMain \n\
");


#define ZwReplaceKey NtReplaceKey
__asm__(".intel_syntax noprefix \n\
NtReplaceKey: \n\
    mov r10, 0x0DD58FCC2 \n\
    call WhisperMain \n\
");


#define ZwReplacePartitionUnit NtReplacePartitionUnit
__asm__(".intel_syntax noprefix \n\
NtReplacePartitionUnit: \n\
    mov r10, 0x0AEAF5BD5 \n\
    call WhisperMain \n\
");


#define ZwReplyWaitReplyPort NtReplyWaitReplyPort
__asm__(".intel_syntax noprefix \n\
NtReplyWaitReplyPort: \n\
    mov r10, 0x0E47EE1EE \n\
    call WhisperMain \n\
");


#define ZwRequestPort NtRequestPort
__asm__(".intel_syntax noprefix \n\
NtRequestPort: \n\
    mov r10, 0x0E073F9F6 \n\
    call WhisperMain \n\
");


#define ZwResetEvent NtResetEvent
__asm__(".intel_syntax noprefix \n\
NtResetEvent: \n\
    mov r10, 0x0DC313C62 \n\
    call WhisperMain \n\
");


#define ZwResetWriteWatch NtResetWriteWatch
__asm__(".intel_syntax noprefix \n\
NtResetWriteWatch: \n\
    mov r10, 0x012DF2E5A \n\
    call WhisperMain \n\
");


#define ZwRestoreKey NtRestoreKey
__asm__(".intel_syntax noprefix \n\
NtRestoreKey: \n\
    mov r10, 0x02BFE4615 \n\
    call WhisperMain \n\
");


#define ZwResumeProcess NtResumeProcess
__asm__(".intel_syntax noprefix \n\
NtResumeProcess: \n\
    mov r10, 0x083D37ABE \n\
    call WhisperMain \n\
");


#define ZwRevertContainerImpersonation NtRevertContainerImpersonation
__asm__(".intel_syntax noprefix \n\
NtRevertContainerImpersonation: \n\
    mov r10, 0x00895C8C7 \n\
    call WhisperMain \n\
");


#define ZwRollbackComplete NtRollbackComplete
__asm__(".intel_syntax noprefix \n\
NtRollbackComplete: \n\
    mov r10, 0x054B85056 \n\
    call WhisperMain \n\
");


#define ZwRollbackEnlistment NtRollbackEnlistment
__asm__(".intel_syntax noprefix \n\
NtRollbackEnlistment: \n\
    mov r10, 0x0D9469E8D \n\
    call WhisperMain \n\
");


#define ZwRollbackRegistryTransaction NtRollbackRegistryTransaction
__asm__(".intel_syntax noprefix \n\
NtRollbackRegistryTransaction: \n\
    mov r10, 0x010B7F7E2 \n\
    call WhisperMain \n\
");


#define ZwRollbackTransaction NtRollbackTransaction
__asm__(".intel_syntax noprefix \n\
NtRollbackTransaction: \n\
    mov r10, 0x003D73B7A \n\
    call WhisperMain \n\
");


#define ZwRollforwardTransactionManager NtRollforwardTransactionManager
__asm__(".intel_syntax noprefix \n\
NtRollforwardTransactionManager: \n\
    mov r10, 0x00D339D2D \n\
    call WhisperMain \n\
");


#define ZwSaveKey NtSaveKey
__asm__(".intel_syntax noprefix \n\
NtSaveKey: \n\
    mov r10, 0x077CB5654 \n\
    call WhisperMain \n\
");


#define ZwSaveKeyEx NtSaveKeyEx
__asm__(".intel_syntax noprefix \n\
NtSaveKeyEx: \n\
    mov r10, 0x01790EBE4 \n\
    call WhisperMain \n\
");


#define ZwSaveMergedKeys NtSaveMergedKeys
__asm__(".intel_syntax noprefix \n\
NtSaveMergedKeys: \n\
    mov r10, 0x025A32A3C \n\
    call WhisperMain \n\
");


#define ZwSecureConnectPort NtSecureConnectPort
__asm__(".intel_syntax noprefix \n\
NtSecureConnectPort: \n\
    mov r10, 0x0128D0102 \n\
    call WhisperMain \n\
");


#define ZwSerializeBoot NtSerializeBoot
__asm__(".intel_syntax noprefix \n\
NtSerializeBoot: \n\
    mov r10, 0x097421756 \n\
    call WhisperMain \n\
");


#define ZwSetBootEntryOrder NtSetBootEntryOrder
__asm__(".intel_syntax noprefix \n\
NtSetBootEntryOrder: \n\
    mov r10, 0x0B16B8BC3 \n\
    call WhisperMain \n\
");


#define ZwSetBootOptions NtSetBootOptions
__asm__(".intel_syntax noprefix \n\
NtSetBootOptions: \n\
    mov r10, 0x007990D1D \n\
    call WhisperMain \n\
");


#define ZwSetCachedSigningLevel NtSetCachedSigningLevel
__asm__(".intel_syntax noprefix \n\
NtSetCachedSigningLevel: \n\
    mov r10, 0x022BB2406 \n\
    call WhisperMain \n\
");


#define ZwSetCachedSigningLevel2 NtSetCachedSigningLevel2
__asm__(".intel_syntax noprefix \n\
NtSetCachedSigningLevel2: \n\
    mov r10, 0x02499AD4E \n\
    call WhisperMain \n\
");


#define ZwSetContextThread NtSetContextThread
__asm__(".intel_syntax noprefix \n\
NtSetContextThread: \n\
    mov r10, 0x0268C2825 \n\
    call WhisperMain \n\
");


#define ZwSetDebugFilterState NtSetDebugFilterState
__asm__(".intel_syntax noprefix \n\
NtSetDebugFilterState: \n\
    mov r10, 0x0D749D8ED \n\
    call WhisperMain \n\
");


#define ZwSetDefaultHardErrorPort NtSetDefaultHardErrorPort
__asm__(".intel_syntax noprefix \n\
NtSetDefaultHardErrorPort: \n\
    mov r10, 0x0FB72E0FD \n\
    call WhisperMain \n\
");


#define ZwSetDefaultLocale NtSetDefaultLocale
__asm__(".intel_syntax noprefix \n\
NtSetDefaultLocale: \n\
    mov r10, 0x0BC24BA98 \n\
    call WhisperMain \n\
");


#define ZwSetDefaultUILanguage NtSetDefaultUILanguage
__asm__(".intel_syntax noprefix \n\
NtSetDefaultUILanguage: \n\
    mov r10, 0x0A40A192F \n\
    call WhisperMain \n\
");


#define ZwSetDriverEntryOrder NtSetDriverEntryOrder
__asm__(".intel_syntax noprefix \n\
NtSetDriverEntryOrder: \n\
    mov r10, 0x0B7998D35 \n\
    call WhisperMain \n\
");


#define ZwSetEaFile NtSetEaFile
__asm__(".intel_syntax noprefix \n\
NtSetEaFile: \n\
    mov r10, 0x0BD2A4348 \n\
    call WhisperMain \n\
");


#define ZwSetHighEventPair NtSetHighEventPair
__asm__(".intel_syntax noprefix \n\
NtSetHighEventPair: \n\
    mov r10, 0x044CC405D \n\
    call WhisperMain \n\
");


#define ZwSetHighWaitLowEventPair NtSetHighWaitLowEventPair
__asm__(".intel_syntax noprefix \n\
NtSetHighWaitLowEventPair: \n\
    mov r10, 0x050D47445 \n\
    call WhisperMain \n\
");


#define ZwSetIRTimer NtSetIRTimer
__asm__(".intel_syntax noprefix \n\
NtSetIRTimer: \n\
    mov r10, 0x0FF5D1906 \n\
    call WhisperMain \n\
");


#define ZwSetInformationDebugObject NtSetInformationDebugObject
__asm__(".intel_syntax noprefix \n\
NtSetInformationDebugObject: \n\
    mov r10, 0x01C21E44D \n\
    call WhisperMain \n\
");


#define ZwSetInformationEnlistment NtSetInformationEnlistment
__asm__(".intel_syntax noprefix \n\
NtSetInformationEnlistment: \n\
    mov r10, 0x0C054E1C2 \n\
    call WhisperMain \n\
");


#define ZwSetInformationJobObject NtSetInformationJobObject
__asm__(".intel_syntax noprefix \n\
NtSetInformationJobObject: \n\
    mov r10, 0x08FA0B52E \n\
    call WhisperMain \n\
");


#define ZwSetInformationKey NtSetInformationKey
__asm__(".intel_syntax noprefix \n\
NtSetInformationKey: \n\
    mov r10, 0x0D859E5FD \n\
    call WhisperMain \n\
");


#define ZwSetInformationResourceManager NtSetInformationResourceManager
__asm__(".intel_syntax noprefix \n\
NtSetInformationResourceManager: \n\
    mov r10, 0x0E3C7FF6A \n\
    call WhisperMain \n\
");


#define ZwSetInformationSymbolicLink NtSetInformationSymbolicLink
__asm__(".intel_syntax noprefix \n\
NtSetInformationSymbolicLink: \n\
    mov r10, 0x06EF76E62 \n\
    call WhisperMain \n\
");


#define ZwSetInformationToken NtSetInformationToken
__asm__(".intel_syntax noprefix \n\
NtSetInformationToken: \n\
    mov r10, 0x08D088394 \n\
    call WhisperMain \n\
");


#define ZwSetInformationTransaction NtSetInformationTransaction
__asm__(".intel_syntax noprefix \n\
NtSetInformationTransaction: \n\
    mov r10, 0x0174BCAE0 \n\
    call WhisperMain \n\
");


#define ZwSetInformationTransactionManager NtSetInformationTransactionManager
__asm__(".intel_syntax noprefix \n\
NtSetInformationTransactionManager: \n\
    mov r10, 0x001B56948 \n\
    call WhisperMain \n\
");


#define ZwSetInformationVirtualMemory NtSetInformationVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtSetInformationVirtualMemory: \n\
    mov r10, 0x019901D1F \n\
    call WhisperMain \n\
");


#define ZwSetInformationWorkerFactory NtSetInformationWorkerFactory
__asm__(".intel_syntax noprefix \n\
NtSetInformationWorkerFactory: \n\
    mov r10, 0x084509CCE \n\
    call WhisperMain \n\
");


#define ZwSetIntervalProfile NtSetIntervalProfile
__asm__(".intel_syntax noprefix \n\
NtSetIntervalProfile: \n\
    mov r10, 0x0EC263464 \n\
    call WhisperMain \n\
");


#define ZwSetIoCompletion NtSetIoCompletion
__asm__(".intel_syntax noprefix \n\
NtSetIoCompletion: \n\
    mov r10, 0x0C030E6A5 \n\
    call WhisperMain \n\
");


#define ZwSetIoCompletionEx NtSetIoCompletionEx
__asm__(".intel_syntax noprefix \n\
NtSetIoCompletionEx: \n\
    mov r10, 0x02695F9C2 \n\
    call WhisperMain \n\
");


#define ZwSetLdtEntries NtSetLdtEntries
__asm__(".intel_syntax noprefix \n\
NtSetLdtEntries: \n\
    mov r10, 0x08CA4FF44 \n\
    call WhisperMain \n\
");


#define ZwSetLowEventPair NtSetLowEventPair
__asm__(".intel_syntax noprefix \n\
NtSetLowEventPair: \n\
    mov r10, 0x011923702 \n\
    call WhisperMain \n\
");


#define ZwSetLowWaitHighEventPair NtSetLowWaitHighEventPair
__asm__(".intel_syntax noprefix \n\
NtSetLowWaitHighEventPair: \n\
    mov r10, 0x004DC004D \n\
    call WhisperMain \n\
");


#define ZwSetQuotaInformationFile NtSetQuotaInformationFile
__asm__(".intel_syntax noprefix \n\
NtSetQuotaInformationFile: \n\
    mov r10, 0x09E3DA8AE \n\
    call WhisperMain \n\
");


#define ZwSetSecurityObject NtSetSecurityObject
__asm__(".intel_syntax noprefix \n\
NtSetSecurityObject: \n\
    mov r10, 0x0D847888B \n\
    call WhisperMain \n\
");


#define ZwSetSystemEnvironmentValue NtSetSystemEnvironmentValue
__asm__(".intel_syntax noprefix \n\
NtSetSystemEnvironmentValue: \n\
    mov r10, 0x01E88F888 \n\
    call WhisperMain \n\
");


#define ZwSetSystemEnvironmentValueEx NtSetSystemEnvironmentValueEx
__asm__(".intel_syntax noprefix \n\
NtSetSystemEnvironmentValueEx: \n\
    mov r10, 0x01C0124BE \n\
    call WhisperMain \n\
");


#define ZwSetSystemInformation NtSetSystemInformation
__asm__(".intel_syntax noprefix \n\
NtSetSystemInformation: \n\
    mov r10, 0x0D9B6DF25 \n\
    call WhisperMain \n\
");


#define ZwSetSystemPowerState NtSetSystemPowerState
__asm__(".intel_syntax noprefix \n\
NtSetSystemPowerState: \n\
    mov r10, 0x0D950A7D2 \n\
    call WhisperMain \n\
");


#define ZwSetSystemTime NtSetSystemTime
__asm__(".intel_syntax noprefix \n\
NtSetSystemTime: \n\
    mov r10, 0x03EAB4F3F \n\
    call WhisperMain \n\
");


#define ZwSetThreadExecutionState NtSetThreadExecutionState
__asm__(".intel_syntax noprefix \n\
NtSetThreadExecutionState: \n\
    mov r10, 0x08204E480 \n\
    call WhisperMain \n\
");


#define ZwSetTimer2 NtSetTimer2
__asm__(".intel_syntax noprefix \n\
NtSetTimer2: \n\
    mov r10, 0x09BD89B16 \n\
    call WhisperMain \n\
");


#define ZwSetTimerEx NtSetTimerEx
__asm__(".intel_syntax noprefix \n\
NtSetTimerEx: \n\
    mov r10, 0x0B54085F8 \n\
    call WhisperMain \n\
");


#define ZwSetTimerResolution NtSetTimerResolution
__asm__(".intel_syntax noprefix \n\
NtSetTimerResolution: \n\
    mov r10, 0x054C27455 \n\
    call WhisperMain \n\
");


#define ZwSetUuidSeed NtSetUuidSeed
__asm__(".intel_syntax noprefix \n\
NtSetUuidSeed: \n\
    mov r10, 0x07458C176 \n\
    call WhisperMain \n\
");


#define ZwSetVolumeInformationFile NtSetVolumeInformationFile
__asm__(".intel_syntax noprefix \n\
NtSetVolumeInformationFile: \n\
    mov r10, 0x01EBFD488 \n\
    call WhisperMain \n\
");


#define ZwSetWnfProcessNotificationEvent NtSetWnfProcessNotificationEvent
__asm__(".intel_syntax noprefix \n\
NtSetWnfProcessNotificationEvent: \n\
    mov r10, 0x01288F19E \n\
    call WhisperMain \n\
");


#define ZwShutdownSystem NtShutdownSystem
__asm__(".intel_syntax noprefix \n\
NtShutdownSystem: \n\
    mov r10, 0x0CCEDF547 \n\
    call WhisperMain \n\
");


#define ZwShutdownWorkerFactory NtShutdownWorkerFactory
__asm__(".intel_syntax noprefix \n\
NtShutdownWorkerFactory: \n\
    mov r10, 0x0C452D8B7 \n\
    call WhisperMain \n\
");


#define ZwSignalAndWaitForSingleObject NtSignalAndWaitForSingleObject
__asm__(".intel_syntax noprefix \n\
NtSignalAndWaitForSingleObject: \n\
    mov r10, 0x0A63B9E97 \n\
    call WhisperMain \n\
");


#define ZwSinglePhaseReject NtSinglePhaseReject
__asm__(".intel_syntax noprefix \n\
NtSinglePhaseReject: \n\
    mov r10, 0x0223C44CF \n\
    call WhisperMain \n\
");


#define ZwStartProfile NtStartProfile
__asm__(".intel_syntax noprefix \n\
NtStartProfile: \n\
    mov r10, 0x0815AD3EF \n\
    call WhisperMain \n\
");


#define ZwStopProfile NtStopProfile
__asm__(".intel_syntax noprefix \n\
NtStopProfile: \n\
    mov r10, 0x0049DCAB8 \n\
    call WhisperMain \n\
");


#define ZwSubscribeWnfStateChange NtSubscribeWnfStateChange
__asm__(".intel_syntax noprefix \n\
NtSubscribeWnfStateChange: \n\
    mov r10, 0x09E39D3E0 \n\
    call WhisperMain \n\
");


#define ZwSuspendProcess NtSuspendProcess
__asm__(".intel_syntax noprefix \n\
NtSuspendProcess: \n\
    mov r10, 0x0315E32C0 \n\
    call WhisperMain \n\
");


#define ZwSuspendThread NtSuspendThread
__asm__(".intel_syntax noprefix \n\
NtSuspendThread: \n\
    mov r10, 0x036932821 \n\
    call WhisperMain \n\
");


#define ZwSystemDebugControl NtSystemDebugControl
__asm__(".intel_syntax noprefix \n\
NtSystemDebugControl: \n\
    mov r10, 0x0019FF3D9 \n\
    call WhisperMain \n\
");


#define ZwTerminateEnclave NtTerminateEnclave
__asm__(".intel_syntax noprefix \n\
NtTerminateEnclave: \n\
    mov r10, 0x060BF7434 \n\
    call WhisperMain \n\
");


#define ZwTerminateJobObject NtTerminateJobObject
__asm__(".intel_syntax noprefix \n\
NtTerminateJobObject: \n\
    mov r10, 0x0049F5245 \n\
    call WhisperMain \n\
");


#define ZwTestAlert NtTestAlert
__asm__(".intel_syntax noprefix \n\
NtTestAlert: \n\
    mov r10, 0x0CF52DAF3 \n\
    call WhisperMain \n\
");


#define ZwThawRegistry NtThawRegistry
__asm__(".intel_syntax noprefix \n\
NtThawRegistry: \n\
    mov r10, 0x0C2A133E8 \n\
    call WhisperMain \n\
");


#define ZwThawTransactions NtThawTransactions
__asm__(".intel_syntax noprefix \n\
NtThawTransactions: \n\
    mov r10, 0x077E74B55 \n\
    call WhisperMain \n\
");


#define ZwTraceControl NtTraceControl
__asm__(".intel_syntax noprefix \n\
NtTraceControl: \n\
    mov r10, 0x03FA9F9F3 \n\
    call WhisperMain \n\
");


#define ZwTranslateFilePath NtTranslateFilePath
__asm__(".intel_syntax noprefix \n\
NtTranslateFilePath: \n\
    mov r10, 0x0FF56FCCD \n\
    call WhisperMain \n\
");


#define ZwUmsThreadYield NtUmsThreadYield
__asm__(".intel_syntax noprefix \n\
NtUmsThreadYield: \n\
    mov r10, 0x08F159CA1 \n\
    call WhisperMain \n\
");


#define ZwUnloadDriver NtUnloadDriver
__asm__(".intel_syntax noprefix \n\
NtUnloadDriver: \n\
    mov r10, 0x0DD6A2061 \n\
    call WhisperMain \n\
");


#define ZwUnloadKey NtUnloadKey
__asm__(".intel_syntax noprefix \n\
NtUnloadKey: \n\
    mov r10, 0x068BD075B \n\
    call WhisperMain \n\
");


#define ZwUnloadKey2 NtUnloadKey2
__asm__(".intel_syntax noprefix \n\
NtUnloadKey2: \n\
    mov r10, 0x033D56F58 \n\
    call WhisperMain \n\
");


#define ZwUnloadKeyEx NtUnloadKeyEx
__asm__(".intel_syntax noprefix \n\
NtUnloadKeyEx: \n\
    mov r10, 0x029E71F58 \n\
    call WhisperMain \n\
");


#define ZwUnlockFile NtUnlockFile
__asm__(".intel_syntax noprefix \n\
NtUnlockFile: \n\
    mov r10, 0x02A7B5CEF \n\
    call WhisperMain \n\
");


#define ZwUnlockVirtualMemory NtUnlockVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtUnlockVirtualMemory: \n\
    mov r10, 0x0FFA8C917 \n\
    call WhisperMain \n\
");


#define ZwUnmapViewOfSectionEx NtUnmapViewOfSectionEx
__asm__(".intel_syntax noprefix \n\
NtUnmapViewOfSectionEx: \n\
    mov r10, 0x04A914E2C \n\
    call WhisperMain \n\
");


#define ZwUnsubscribeWnfStateChange NtUnsubscribeWnfStateChange
__asm__(".intel_syntax noprefix \n\
NtUnsubscribeWnfStateChange: \n\
    mov r10, 0x0EA3FB7FE \n\
    call WhisperMain \n\
");


#define ZwUpdateWnfStateData NtUpdateWnfStateData
__asm__(".intel_syntax noprefix \n\
NtUpdateWnfStateData: \n\
    mov r10, 0x0CD02DFB3 \n\
    call WhisperMain \n\
");


#define ZwVdmControl NtVdmControl
__asm__(".intel_syntax noprefix \n\
NtVdmControl: \n\
    mov r10, 0x08B9012A6 \n\
    call WhisperMain \n\
");


#define ZwWaitForAlertByThreadId NtWaitForAlertByThreadId
__asm__(".intel_syntax noprefix \n\
NtWaitForAlertByThreadId: \n\
    mov r10, 0x046BA6C7D \n\
    call WhisperMain \n\
");


#define ZwWaitForDebugEvent NtWaitForDebugEvent
__asm__(".intel_syntax noprefix \n\
NtWaitForDebugEvent: \n\
    mov r10, 0x000CF1D66 \n\
    call WhisperMain \n\
");


#define ZwWaitForKeyedEvent NtWaitForKeyedEvent
__asm__(".intel_syntax noprefix \n\
NtWaitForKeyedEvent: \n\
    mov r10, 0x090CA6AAD \n\
    call WhisperMain \n\
");


#define ZwWaitForWorkViaWorkerFactory NtWaitForWorkViaWorkerFactory
__asm__(".intel_syntax noprefix \n\
NtWaitForWorkViaWorkerFactory: \n\
    mov r10, 0x0F8AED47B \n\
    call WhisperMain \n\
");


#define ZwWaitHighEventPair NtWaitHighEventPair
__asm__(".intel_syntax noprefix \n\
NtWaitHighEventPair: \n\
    mov r10, 0x0D34FC1D0 \n\
    call WhisperMain \n\
");


#define ZwWaitLowEventPair NtWaitLowEventPair
__asm__(".intel_syntax noprefix \n\
NtWaitLowEventPair: \n\
    mov r10, 0x0B4165C0B \n\
    call WhisperMain \n\
");


#define ZwAcquireCMFViewOwnership NtAcquireCMFViewOwnership
__asm__(".intel_syntax noprefix \n\
NtAcquireCMFViewOwnership: \n\
    mov r10, 0x06AD32A5C \n\
    call WhisperMain \n\
");


#define ZwCancelDeviceWakeupRequest NtCancelDeviceWakeupRequest
__asm__(".intel_syntax noprefix \n\
NtCancelDeviceWakeupRequest: \n\
    mov r10, 0x0F7BC10D7 \n\
    call WhisperMain \n\
");


#define ZwClearAllSavepointsTransaction NtClearAllSavepointsTransaction
__asm__(".intel_syntax noprefix \n\
NtClearAllSavepointsTransaction: \n\
    mov r10, 0x0C089E259 \n\
    call WhisperMain \n\
");


#define ZwClearSavepointTransaction NtClearSavepointTransaction
__asm__(".intel_syntax noprefix \n\
NtClearSavepointTransaction: \n\
    mov r10, 0x0F56929C7 \n\
    call WhisperMain \n\
");


#define ZwRollbackSavepointTransaction NtRollbackSavepointTransaction
__asm__(".intel_syntax noprefix \n\
NtRollbackSavepointTransaction: \n\
    mov r10, 0x0D843FA97 \n\
    call WhisperMain \n\
");


#define ZwSavepointTransaction NtSavepointTransaction
__asm__(".intel_syntax noprefix \n\
NtSavepointTransaction: \n\
    mov r10, 0x09813DAC7 \n\
    call WhisperMain \n\
");


#define ZwSavepointComplete NtSavepointComplete
__asm__(".intel_syntax noprefix \n\
NtSavepointComplete: \n\
    mov r10, 0x088DA86B3 \n\
    call WhisperMain \n\
");


#define ZwCreateSectionEx NtCreateSectionEx
__asm__(".intel_syntax noprefix \n\
NtCreateSectionEx: \n\
    mov r10, 0x0B053F2E9 \n\
    call WhisperMain \n\
");


#define ZwCreateCrossVmEvent NtCreateCrossVmEvent
__asm__(".intel_syntax noprefix \n\
NtCreateCrossVmEvent: \n\
    mov r10, 0x0FE3CC196 \n\
    call WhisperMain \n\
");


#define ZwGetPlugPlayEvent NtGetPlugPlayEvent
__asm__(".intel_syntax noprefix \n\
NtGetPlugPlayEvent: \n\
    mov r10, 0x000902D08 \n\
    call WhisperMain \n\
");


#define ZwListTransactions NtListTransactions
__asm__(".intel_syntax noprefix \n\
NtListTransactions: \n\
    mov r10, 0x08525A983 \n\
    call WhisperMain \n\
");


#define ZwMarshallTransaction NtMarshallTransaction
__asm__(".intel_syntax noprefix \n\
NtMarshallTransaction: \n\
    mov r10, 0x0905B92CF \n\
    call WhisperMain \n\
");


#define ZwPullTransaction NtPullTransaction
__asm__(".intel_syntax noprefix \n\
NtPullTransaction: \n\
    mov r10, 0x0900BD6DB \n\
    call WhisperMain \n\
");


#define ZwReleaseCMFViewOwnership NtReleaseCMFViewOwnership
__asm__(".intel_syntax noprefix \n\
NtReleaseCMFViewOwnership: \n\
    mov r10, 0x08E15828E \n\
    call WhisperMain \n\
");


#define ZwWaitForWnfNotifications NtWaitForWnfNotifications
__asm__(".intel_syntax noprefix \n\
NtWaitForWnfNotifications: \n\
    mov r10, 0x0DC8FDA1C \n\
    call WhisperMain \n\
");


#define ZwStartTm NtStartTm
__asm__(".intel_syntax noprefix \n\
NtStartTm: \n\
    mov r10, 0x0031E49A0 \n\
    call WhisperMain \n\
");


#define ZwSetInformationProcess NtSetInformationProcess
__asm__(".intel_syntax noprefix \n\
NtSetInformationProcess: \n\
    mov r10, 0x08117868C \n\
    call WhisperMain \n\
");


#define ZwRequestDeviceWakeup NtRequestDeviceWakeup
__asm__(".intel_syntax noprefix \n\
NtRequestDeviceWakeup: \n\
    mov r10, 0x0359314C2 \n\
    call WhisperMain \n\
");


#define ZwRequestWakeupLatency NtRequestWakeupLatency
__asm__(".intel_syntax noprefix \n\
NtRequestWakeupLatency: \n\
    mov r10, 0x09801A1BC \n\
    call WhisperMain \n\
");


#define ZwQuerySystemTime NtQuerySystemTime
__asm__(".intel_syntax noprefix \n\
NtQuerySystemTime: \n\
    mov r10, 0x0B9A357A9 \n\
    call WhisperMain \n\
");


#define ZwManageHotPatch NtManageHotPatch
__asm__(".intel_syntax noprefix \n\
NtManageHotPatch: \n\
    mov r10, 0x0A0BF2EA8 \n\
    call WhisperMain \n\
");


#define ZwContinueEx NtContinueEx
__asm__(".intel_syntax noprefix \n\
NtContinueEx: \n\
    mov r10, 0x05FC5BBB9 \n\
    call WhisperMain \n\
");


