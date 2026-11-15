// Primorsk: диагностика падений клиента omp-cef.
// При исключениях доступа к памяти и повреждении кучи пишет в
// "Documents\GTA San Andreas User Files\cef\crash.log": код, адрес, модуль+смещение,
// регистры и цепочку вызовов с именами функций и строками (если рядом с client.dll лежит client.pdb).
// Ловит первые исключения (first-chance), поэтому часть записей может относиться к обработанным
// ошибкам (например, проверкам указателей); решающими считаются последние записи перед падением.

#include "crash_diag.hpp"

#include <windows.h>
#include <dbghelp.h>
#include <shlobj.h>

#include <atomic>
#include <cstdio>
#include <cwchar>

namespace
{
    std::atomic<int> g_logged{ 0 };
    constexpr int kMaxEntries = 12;
    wchar_t g_logPath[MAX_PATH] = {};
    wchar_t g_symPath[MAX_PATH] = {};
    PVOID g_handler = nullptr;
    CRITICAL_SECTION g_lock;
    bool g_symInit = false;

    void AppendLine(HANDLE file, const char* text)
    {
        DWORD written = 0;
        WriteFile(file, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
    }

    void DescribeAddress(DWORD64 address, char* out, size_t outSize)
    {
        HMODULE module = nullptr;
        char moduleName[MAX_PATH] = "?";
        DWORD64 moduleBase = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(address)), &module) && module)
        {
            char full[MAX_PATH] = {};
            if (GetModuleFileNameA(module, full, MAX_PATH))
            {
                const char* slash = strrchr(full, '\\');
                strncpy_s(moduleName, slash ? slash + 1 : full, _TRUNCATE);
            }
            moduleBase = reinterpret_cast<DWORD64>(module);
        }

        char symbolText[512] = "";
        if (g_symInit)
        {
            alignas(SYMBOL_INFO) char buffer[sizeof(SYMBOL_INFO) + 256] = {};
            auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = 255;
            DWORD64 displacement = 0;
            if (SymFromAddr(GetCurrentProcess(), address, &displacement, symbol))
            {
                IMAGEHLP_LINE64 line{};
                line.SizeOfStruct = sizeof(line);
                DWORD lineDisplacement = 0;
                if (SymGetLineFromAddr64(GetCurrentProcess(), address, &lineDisplacement, &line))
                    _snprintf_s(symbolText, _TRUNCATE, " %s+0x%llx (%s:%lu)", symbol->Name,
                        static_cast<unsigned long long>(displacement), line.FileName, line.LineNumber);
                else
                    _snprintf_s(symbolText, _TRUNCATE, " %s+0x%llx", symbol->Name, static_cast<unsigned long long>(displacement));
            }
        }

        _snprintf_s(out, outSize, _TRUNCATE, "0x%08llx %s+0x%llx%s",
            static_cast<unsigned long long>(address), moduleName,
            static_cast<unsigned long long>(address - moduleBase), symbolText);
    }

    bool IsInteresting(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_ACCESS_VIOLATION:      // c0000005
        case 0xC0000374:                      // повреждение кучи
        case 0xC0000409:                      // переполнение буфера в стеке / fail fast
        case EXCEPTION_STACK_OVERFLOW:        // c00000fd
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            return true;
        default:
            return false;
        }
    }

    LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS info)
    {
        if (!info || !info->ExceptionRecord || !IsInteresting(info->ExceptionRecord->ExceptionCode))
            return EXCEPTION_CONTINUE_SEARCH;
        if (g_logged.fetch_add(1) >= kMaxEntries)
            return EXCEPTION_CONTINUE_SEARCH;

        EnterCriticalSection(&g_lock);
        HANDLE file = CreateFileW(g_logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            const auto* rec = info->ExceptionRecord;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char line[1024];
            char where[700];
            DescribeAddress(reinterpret_cast<DWORD64>(rec->ExceptionAddress), where, sizeof(where));
            _snprintf_s(line, _TRUNCATE, "==== %04u-%02u-%02u %02u:%02u:%02u.%03u поток %lu: исключение 0x%08lx в %s",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                GetCurrentThreadId(), rec->ExceptionCode, where);
            AppendLine(file, line);

            if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
            {
                const ULONG_PTR kind = rec->ExceptionInformation[0];
                _snprintf_s(line, _TRUNCATE, "     доступ: %s по адресу 0x%08llx",
                    kind == 0 ? "чтение" : (kind == 1 ? "запись" : "исполнение"),
                    static_cast<unsigned long long>(rec->ExceptionInformation[1]));
                AppendLine(file, line);
            }

#if defined(_M_IX86)
            CONTEXT ctx = *info->ContextRecord;
            _snprintf_s(line, _TRUNCATE, "     EIP=%08lx ESP=%08lx EBP=%08lx EAX=%08lx EBX=%08lx ECX=%08lx EDX=%08lx ESI=%08lx EDI=%08lx",
                ctx.Eip, ctx.Esp, ctx.Ebp, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi);
            AppendLine(file, line);

            STACKFRAME64 frame{};
            frame.AddrPC.Offset = ctx.Eip;
            frame.AddrPC.Mode = AddrModeFlat;
            frame.AddrFrame.Offset = ctx.Ebp;
            frame.AddrFrame.Mode = AddrModeFlat;
            frame.AddrStack.Offset = ctx.Esp;
            frame.AddrStack.Mode = AddrModeFlat;
            for (int i = 0; i < 32; ++i)
            {
                if (!StackWalk64(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), GetCurrentThread(), &frame, &ctx,
                        nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
                    break;
                if (frame.AddrPC.Offset == 0)
                    break;
                DescribeAddress(frame.AddrPC.Offset, where, sizeof(where));
                _snprintf_s(line, _TRUNCATE, "     #%02d %s", i, where);
                AppendLine(file, line);
            }
#endif
            CloseHandle(file);
        }
        LeaveCriticalSection(&g_lock);
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

void CrashDiag_Install(HMODULE self)
{
    if (g_handler)
        return;

    InitializeCriticalSection(&g_lock);

    wchar_t docs[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, docs)))
        _snwprintf_s(g_logPath, _TRUNCATE, L"%s\\GTA San Andreas User Files\\cef\\crash.log", docs);
    else
        wcsncpy_s(g_logPath, L"crash.log", _TRUNCATE);

    // Символы ищем рядом с client.dll (client.pdb кладётся туда только для диагностики).
    if (GetModuleFileNameW(self, g_symPath, MAX_PATH))
    {
        wchar_t* slash = wcsrchr(g_symPath, L'\\');
        if (slash)
            *slash = L'\0';
    }
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS);
    char symPathA[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_ACP, 0, g_symPath, -1, symPathA, sizeof(symPathA), nullptr, nullptr);
    g_symInit = SymInitialize(GetCurrentProcess(), symPathA, TRUE) != FALSE;

    g_handler = AddVectoredExceptionHandler(1, VectoredHandler);
}

void CrashDiag_Uninstall()
{
    if (!g_handler)
        return;
    RemoveVectoredExceptionHandler(g_handler);
    g_handler = nullptr;
}
