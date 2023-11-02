#include "context.h"
#include "hooks.h"

int __stdcall DllMain(_In_ HINSTANCE instance, _In_ DWORD reason, _In_ LPVOID reserved) {
	if (reason != DLL_PROCESS_ATTACH)
		return 0;

	DisableThreadLibraryCalls(instance);

	CreateThread(NULL, NULL, reinterpret_cast <LPTHREAD_START_ROUTINE> (TestFunc), NULL, NULL, NULL);

	return 1;
}