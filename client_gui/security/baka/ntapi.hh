#pragma once
#include "struct.hh"

#include "../../xorstr/xorstr.h"

typedef   NTSTATUS( NTAPI* t_ZwOpenSection )
(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);





typedef   NTSTATUS( NTAPI* t_ZwMapViewOfSection )
(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

typedef   NTSTATUS( NTAPI* t_NtClose )
(
	HANDLE Handle
	);

typedef   NTSTATUS( NTAPI* t_ZwUnmapViewOfSection )
(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);



typedef NTSTATUS( NTAPI* t_NtQueryInformationProcess )
(



	IN HANDLE               ProcessHandle,
	IN processinfoclass ProcessInformationClass,
	OUT PVOID               ProcessInformation,
	IN ULONG                ProcessInformationLength,
	OUT PULONG              ReturnLength
	);

typedef NTSTATUS( NTAPI* t_NtSetInformationThread )(



	IN HANDLE               ThreadHandle,
	IN threadinfoclass ThreadInformationClass,
	IN PVOID                ThreadInformation,
	IN ULONG                ThreadInformationLength );



typedef NTSTATUS( NTAPI* t_NtQuerySystemInformation )
(
	_system_information_class SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS( NTAPI* t_NtQueryInformationThread )
(



	IN HANDLE               ThreadHandle,
	IN threadinfoclass ThreadInformationClass,
	OUT PVOID               ThreadInformation,
	IN ULONG                ThreadInformationLength,
	OUT PULONG              ReturnLength OPTIONAL );




typedef  NTSTATUS( NTAPI* t_NtReadVirtualMemory )
(



	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL );



typedef  NTSTATUS( NTAPI* t_NtAllocateVirtualMemory )(



	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect );
typedef  NTSTATUS( NTAPI* t_RtlGetVersion )
(
	PRTL_OSVERSIONINFOW lpVersionInformation
	);


typedef  NTSTATUS( NTAPI* t_NtSetInformationProcess )
(



	IN HANDLE               ProcessHandle,
	IN processinfoclass ProcessInformationClass,
	IN PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength );


NTSTATUS
NTAPI
NtSystemDebugControl
(

	IN SYSDBG_COMMAND       Command,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength,
	OUT PULONG              ReturnLength OPTIONAL
);

NTSTATUS
NTAPI
ntquerysysteminformation
(
	IN system_information_class SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL );


NTSTATUS
NTAPI
NtSetInformationObject
(
	HANDLE               ObjectHandle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                ObjectInformation,
	ULONG                Length
);


NTSTATUS
NTAPI
NtDuplicateObject
(

	HANDLE               SourceProcessHandle,
	HANDLE               SourceHandle,
	HANDLE               TargetProcessHandle,
	PHANDLE              TargetHandle,
	ACCESS_MASK          DesiredAccess,
	ULONG               InheritHandle,
	ULONG                Options
);

NTSTATUS
NTAPI
NtRemoveProcessDebug
(
	HANDLE               ProcessHandle,
	HANDLE               DebugObjectHandle );

NTSTATUS
NTAPI
NtCreateDebugObject
(
	PHANDLE DebugObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags
);

NTSTATUS
NTAPI
NtQueryObject
(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);

NTSTATUS
NTAPI
NtClose
(
	HANDLE Handle
);

NTSTATUS
NTAPI
NtGetContextThread
(
	HANDLE ThreadHandle,
	PCONTEXT Context
);


NTSTATUS
NTAPI
NtSetContextThread
(
	HANDLE ThreadHandle,
	PCONTEXT Context
);