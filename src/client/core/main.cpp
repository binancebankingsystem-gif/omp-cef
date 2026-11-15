#include <windows.h>
#include <memory>

#include "runtime.hpp"
#include "system/crash_diag.hpp"

static std::unique_ptr<Runtime> runtime;
static HMODULE g_selfModule = nullptr;

DWORD WINAPI AppInitializationThread(LPVOID)
{
	// Primorsk: диагностика падений — вне блокировки загрузчика (SymInitialize в DllMain может зависнуть).
	CrashDiag_Install(g_selfModule);
	runtime = Runtime::CreateDefault();
    runtime->Start();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_selfModule = hModule;

        HANDLE hThread = CreateThread(nullptr, 0, AppInitializationThread, nullptr, 0, nullptr);
        if (hThread) {
            CloseHandle(hThread);
        } 
        else {
            MessageBoxA(nullptr, "Failed to create initialization thread.", "Error", MB_ICONERROR);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        CrashDiag_Uninstall();
        if (runtime) {
            runtime->Stop();
            runtime.reset();
        }
        
    }

    return TRUE;
}