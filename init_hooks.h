#pragma once

#include "context.h"
#include "hooks.h"

EXTERN_C NTSTATUS NTAPI ZwWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded
);

HOOKINIT(
	WriteProcessMemory_f,								// the type created 
	WriteProcessMemory,								// the function prototyped
	WriteProcessMemory_t,							// the trampoline to the original function
	WriteProcessMemory_p						// the prologue object of the function used for this hook
)
HOOKINIT(
	NtWriteVirtualMemory_f,								// the type created 
	ZwWriteVirtualMemory,								// the function prototyped
	NtWriteVirtualMemory_t,							// the trampoline to the original function
	NtWriteVirtualMemory_p						// the prologue object of the function used for this hook
)
HOOKINIT(
	VirtualAllocEx_f,								// the type created 
	VirtualAllocEx,								// the function prototyped
	VirtualAllocEx_t,							// the trampoline to the original function
	VirtualAllocEx_p						// the prologue object of the function used for this hook
)
HOOKINIT(
	VirtualAlloc_f,								// the type created 
	VirtualAlloc,								// the function prototyped
	VirtualAlloc_t,							// the trampoline to the original function
	VirtualAlloc_p						// the prologue object of the function used for this hook
)
HOOKINIT(
	LoadLibraryA_f,								// the type created 
	LoadLibraryA,								// the function prototyped
	LoadLibraryA_t,							// the trampoline to the original function
	LoadLibraryA_p						// the prologue object of the function used for this hook
)
HOOKINIT(
	CreateRemoteThread_f,
	CreateRemoteThread, 
	CreateRemoteThread_t,
	CreateRemoteThread_p
)