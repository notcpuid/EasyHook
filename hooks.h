#pragma once

#include "context.h"

#define HOOKINIT(functor_type, function, trampoline_name, prologue_name) \
	using functor_type = decltype(&function); \
	functor_type trampoline_name = NULL; \
	easyhook::prologue prologue_name;

namespace easyhook {
#	define PACKED(s) __pragma(pack(push, 1)) s __pragma(pack(pop))
#	define FUNCTOR(function) decltype(&function)

	union prologue {
		PACKED(struct {
			CHAR jmp;
			ULONG addr;
		}) parts;
		CHAR bytes[sizeof(ULONGLONG)];
		ULONGLONG full = 0;
	};

	enum opcode {
		LONGJUMP_SIZE = 0x05,
		RELJUMP = 0xe9,
		NOP = 0x90,
	};

	class hook32 {
		static const SIZE_T jumpSize = 5;
	public:
		hook32() {};

		LPVOID hook(LPVOID target, prologue& original, LPVOID hook) const {
			LPVOID trampoline = NULL;
			DWORD oldProtection = 0;
			
			if (jumpSize < 5) return 0;																								// minimum jump size of 5. Necessary for 32-bit programs
			
			if (!VirtualProtect((LPVOID)target, 1, PAGE_EXECUTE_READWRITE, &oldProtection))
				return NULL;
			
			if (!(trampoline = VirtualAlloc(NULL, 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
				return VirtualProtect((LPVOID)target, 1, oldProtection, &oldProtection), NULL;

			memcpy(trampoline, target, jumpSize);																					// save the first 5 bytes of the original function in the trampoline
			*((PCHAR)((ULONG)trampoline + jumpSize)) = opcode::RELJUMP;																// relative jump on the 6th byte...
			*((PULONG)((ULONG)trampoline + jumpSize + 1)) = (ULONG)target - (ULONG)trampoline - opcode::LONGJUMP_SIZE;				// return back to the target

			memcpy(&original, target, sizeof original);																				// save the full original first 8 bytes from the function in a member variable
			prologue tmp = original;																								// copy the original 8 bytes so we don't overwrite anything important.
			tmp.parts.jmp = opcode::RELJUMP;																						// set the first byte to a relative jmp
			*(PULONG)(tmp.bytes + 1) = (ULONG)hook - (ULONG)target - opcode::LONGJUMP_SIZE;											// jmp to the trampoline
			InterlockedExchange64((PLONGLONG)target, tmp.full);																		// atomically exchange the first 8 bytes of the original instruction

			VirtualProtect((LPVOID)target, 1, oldProtection, &oldProtection);														// reset the target permissions
			
			return trampoline;
		}

		bool unhook(LPVOID trampoline, prologue original) const {
			DWORD oldProtection = 0;
			prologue origFunc;																										// a place to restore the original function to retrieve the address
			memcpy(&origFunc, (LPVOID)((ULONG)trampoline + jumpSize), sizeof origFunc);												// get the 8 bytes from the trampoline
			PULONG target = (PULONG)(origFunc.parts.addr + opcode::LONGJUMP_SIZE + (ULONG)trampoline);								// get the address and offset it to get the original
			
			if (!VirtualProtect((LPVOID)target, 1, PAGE_EXECUTE_READWRITE, &oldProtection))											// give RWX permissions to the target function
				return false;
			
			InterlockedExchange64((PLONGLONG)target, original.full);																// replace the 8 bytes of the original function with the original bytes.
			VirtualProtect((LPVOID)target, 1, oldProtection, &oldProtection);														// restore the original function permissions
			VirtualFree(trampoline, 0, MEM_RELEASE);
			
			return true;
		}
	};
}

void TestFunc();
