#include "hooks.h"
#include "init_hooks.h"
#include "depends.h"

easyhook::hook32 hooker;

HMODULE __stdcall LoadLibraryA_h(LPCSTR lpLibFileName) {
	
	if (LoadLibraryA_t) {
		HMODULE original_fn = LoadLibraryA_t(lpLibFileName);

		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] Module [" << lpLibFileName << "] loaded via LoadLibraryA" << std::endl;
		myfile.close();

		return original_fn;
	}
}

INT __stdcall WriteProcessMemory_h(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, 
	SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {

	if (WriteProcessMemory_t && nSize > 0) {

		INT original_fn = WriteProcessMemory_t(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] WriteProcessMemory from [0x" << lpBuffer << "]" << " >> [0x" << lpBaseAddress << "] : " << nSize << std::endl;
		myfile.close();

		std::ofstream mydll;
		mydll.open(depends::PathToSave("\\dumped_image.dll"), std::ios_base::app | std::ios::binary);
		if (mydll.is_open()) {
			mydll.write(reinterpret_cast<const char*>(lpBuffer), nSize);
			mydll.close();
		}

		return original_fn;
	}
};

INT __stdcall NtWriteVirtualMemory_h(HANDLE pHandle, PVOID BaseAddress, PVOID Buffer, 
	ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {

	if (NtWriteVirtualMemory_t && NumberOfBytesToWrite > 0) {
		INT original_fn = NtWriteVirtualMemory_t(pHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] NtWriteVirtualMemory from [0x" << Buffer << "]" << " >> [0x" << BaseAddress << "] : " << NumberOfBytesToWrite << std::endl;
		myfile.close();

		return original_fn;
	}
};

LPVOID __stdcall VirtualAllocEx_h(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, 
	DWORD flAllocationType, DWORD flProtect) {

	if (VirtualAllocEx_t && dwSize > 0) { 
		LPVOID original_fn = VirtualAllocEx_t(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);

		/* 
			also known as VirtualAllocExNuma
			using original_fn bc this function is returned baseaddr
			v7 = NtAllocateVirtualMemory(hProcess, &BaseAddress, 0i64, &RegionSize, AllocationType, flProtect);
			if (v7 >= 0)
				return BaseAddress;
		*/
		myfile << "[ > ] VirtualAllocEx at [0x" << original_fn << "]" << " : " << dwSize << std::endl;
		myfile.close();

		return original_fn;
	}
}

LPVOID __stdcall VirtualAlloc_h(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (VirtualAlloc_t && dwSize > 0) {
		LPVOID original_fn = VirtualAlloc_t(lpAddress, dwSize, flAllocationType, flProtect);
		
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] VirtualAlloc at [0x" << original_fn << "]" << " : " << dwSize << std::endl;
		myfile.close();

		return original_fn;
	}
}

HANDLE __stdcall CreateRemoteThread_h(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, 
	LPDWORD lpThreadId) {

	if (CreateRemoteThread_t) {
		HANDLE original_fn = CreateRemoteThread_t(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
		
		std::ofstream myfile;
		myfile.open(depends::PathToSave("\\log.txt"), std::ios_base::app);
		myfile << "[ > ] CreateRemoteThread called with parameter [" << lpParameter << "] " << "remote address [0x" << lpStartAddress << "]" 
			<< " PE allocated address [0x" << reinterpret_cast<LPVOID>(reinterpret_cast<char*>(lpStartAddress) - 0x1001C) << "]" << std::endl;
		myfile.close();

		return original_fn;
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