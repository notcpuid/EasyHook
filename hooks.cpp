#include "hooks.h"
#include "init_hooks.h"
#include "depends.h"

easyhook::hook32 hooker;

HMODULE __stdcall LoadLibraryA_h(LPCSTR lpLibFileName) {
	
	if (LoadLibraryA_t) {
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] Module [" << lpLibFileName << "] loaded via LoadLibraryA" << std::endl;
		myfile.close();

		return LoadLibraryA_t(lpLibFileName);
	}
}

int __stdcall WriteProcessMemory_h(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, 
	SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {

	if (WriteProcessMemory_t && nSize > 0) {
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] WriteProcessMemory from [0x" << lpBuffer << "]" << " >> [0x" << lpBaseAddress << "] : " << nSize << std::endl;
		myfile.close();

		return WriteProcessMemory_t(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
};

int __stdcall NtWriteVirtualMemory_h(HANDLE pHandle, PVOID BaseAddress, PVOID Buffer, 
	ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {

	if (NtWriteVirtualMemory_t && NumberOfBytesToWrite > 0) {
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] NtWriteVirtualMemory from [0x" << Buffer << "]" << " >> [0x" << BaseAddress << "] : " << NumberOfBytesToWrite << std::endl;
		myfile.close();

		return NtWriteVirtualMemory_t(pHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	}
};

LPVOID __stdcall VirtualAllocEx_h(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, 
	DWORD flAllocationType, DWORD flProtect) {

	if (VirtualAllocEx_t && dwSize > 0) {

		LPVOID base = VirtualAllocEx_t(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] VirtualAllocEx at [0x" << base << "]" << " : " << dwSize << std::endl;
		myfile.close();

		return base;
	}
}

LPVOID __stdcall VirtualAlloc_h(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (VirtualAlloc_t && dwSize > 0) {
		LPVOID base = VirtualAlloc_t(lpAddress, dwSize, flAllocationType, flProtect);
		
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] VirtualAlloc at [0x" << base << "]" << " : " << dwSize << std::endl;
		myfile.close();

		return base;
	}
}

HANDLE __stdcall CreateRemoteThread_h(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, 
	LPDWORD lpThreadId) {

	if (CreateRemoteThread_t) {
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] CreateRemoteThread called with parameter [" << lpParameter << "] " << "remote address [0x" << lpStartAddress << "]" 
			<< " PE allocated address [0x" << reinterpret_cast<LPVOID>(reinterpret_cast<char*>(lpStartAddress) - 0x1001C) << "]" << std::endl;
		myfile.close();

		return CreateRemoteThread_t(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	}
}

void HookContext() {
	FARPROC WriteProcessMemory_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
	FARPROC NtWriteVirtualMemory_addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	FARPROC LoadLibraryA_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	FARPROC VirtualAllocEx_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
	FARPROC VirtualAlloc_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	FARPROC CreateRemoteThread_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread");

	WriteProcessMemory_t = (WriteProcessMemory_f)hooker.hook(WriteProcessMemory_addr, WriteProcessMemory_p, WriteProcessMemory_h);
	NtWriteVirtualMemory_t = (NtWriteVirtualMemory_f)hooker.hook(NtWriteVirtualMemory_addr, NtWriteVirtualMemory_p, NtWriteVirtualMemory_h);
	
	LoadLibraryA_t = (LoadLibraryA_f)hooker.hook(LoadLibraryA_addr, LoadLibraryA_p, LoadLibraryA_h);
	
	VirtualAllocEx_t = (VirtualAllocEx_f)hooker.hook(VirtualAllocEx_addr, VirtualAllocEx_p, VirtualAllocEx_h);
	VirtualAlloc_t = (VirtualAlloc_f)hooker.hook(VirtualAlloc_addr, VirtualAlloc_p, VirtualAlloc_h);
	CreateRemoteThread_t = (CreateRemoteThread_f)hooker.hook(CreateRemoteThread_addr, CreateRemoteThread_p, CreateRemoteThread_h);

	MessageBoxA(NULL, "hook is done", "test", NULL);

	return;
}

void TestFunc() {
	AllocConsole();

	printf("[ > ] start hooking...");

	HookContext();
}