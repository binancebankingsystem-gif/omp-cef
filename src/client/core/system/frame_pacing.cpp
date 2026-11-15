// Primorsk: снятие предела 100 к/с SA:MP и свой ограничитель кадров (см. frame_pacing.hpp).
//
// Откуда предел. Виртуальный метод кадра SA:MP (0.3.7-R5: samp.dll+0xA1C10, 0.3.DL-R1: +0xA1A30) после
// кадра делает паузу. При выключенном Frame Limiter игры (байт 0xBA6794 == 0) ветка такая:
//     sub  esi, eax          ; esi = мс с прошлого кадра
//     je   done
//     cmp  esi, 0Bh          ; 83 FE 0B
//     jge  done              ; 7D 0E
//     mov  edx, 0Ah          ; BA 0A 00 00 00
//     sub  edx, esi          ; 2B D6
//     push edx               ; 52
//     call [Sleep]           ; FF 15 ...
// то есть кадр не короче 10 мс — ровно 100 к/с. Замена jge (7D) на jmp (EB) убирает только эту паузу;
// ветка с включённым Frame Limiter (/fpslimit) и особая ветка ~45 к/с не трогаются.

#include "frame_pacing.hpp"

#include "system/logger.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace
{
    constexpr uint8_t kPattern[] = { 0x83, 0xFE, 0x0B, 0x7D, 0x0E, 0xBA, 0x0A, 0x00, 0x00, 0x00, 0x2B, 0xD6, 0x52, 0xFF, 0x15 };
    constexpr size_t kJumpOffset = 3;
    constexpr uint8_t kJge = 0x7D;
    constexpr uint8_t kJmp = 0xEB;

    // CMenuManager::m_bPrefsFrameLimiter (FrontEndMenuManager 0xBA6748 + 0x4C), его же читает samp.dll.
    constexpr uintptr_t kFrameLimiterFlag = 0xBA6794;

    constexpr int kMinFps = 20;
    constexpr int kMaxFps = 1000;

    std::atomic<int> g_limitFps{ 0 };
    LARGE_INTEGER g_freq{};
    int64_t g_last = 0;
    HANDLE g_timer = nullptr;

    bool Matches(const uint8_t* p, uint8_t jump)
    {
        for (size_t i = 0; i < sizeof(kPattern); ++i)
        {
            const uint8_t want = (i == kJumpOffset) ? jump : kPattern[i];
            if (p[i] != want)
                return false;
        }
        return true;
    }

    bool FindTextSection(HMODULE module, uint8_t*& begin, size_t& size)
    {
        auto* base = reinterpret_cast<uint8_t*>(module);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;
        const auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if (std::memcmp(section->Name, ".text", 5) == 0)
            {
                begin = base + section->VirtualAddress;
                size = section->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    int64_t Now()
    {
        LARGE_INTEGER t;
        QueryPerformanceCounter(&t);
        return t.QuadPart;
    }

    // Ждёт до момента target (в тиках QPC): основную часть — таймером, последние ~1 мс — коротким ожиданием.
    void WaitUntil(int64_t target)
    {
        const int64_t tickPerMs = g_freq.QuadPart / 1000;
        int64_t remaining = target - Now();
        if (remaining > 2 * tickPerMs)
        {
            if (!g_timer)
            {
                g_timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
                if (!g_timer)
                    g_timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
            }
            if (g_timer)
            {
                LARGE_INTEGER due;
                // единицы 100 нс, отрицательное — относительное время; оставляем 1 мс на добор
                due.QuadPart = -((remaining - tickPerMs) * 10000000LL / g_freq.QuadPart);
                if (SetWaitableTimer(g_timer, &due, 0, nullptr, nullptr, FALSE))
                    WaitForSingleObject(g_timer, 100);
            }
        }
        while (Now() < target)
            YieldProcessor();
    }
}

namespace frame_pacing
{
    bool UnlockSampFrameCap(HMODULE samp)
    {
        uint8_t* text = nullptr;
        size_t size = 0;
        if (!samp || !FindTextSection(samp, text, size) || size < sizeof(kPattern))
        {
            LOG_WARN("[FramePacing] samp.dll: .text section not found, 100 FPS cap left as is.");
            return false;
        }

        uint8_t* found = nullptr;
        int count = 0;
        int alreadyPatched = 0;
        for (size_t i = 0; i + sizeof(kPattern) <= size; ++i)
        {
            if (Matches(text + i, kJge))
            {
                found = text + i;
                ++count;
            }
            else if (Matches(text + i, kJmp))
            {
                ++alreadyPatched;
            }
        }

        if (count == 0 && alreadyPatched == 1)
        {
            LOG_INFO("[FramePacing] SA-MP 100 FPS cap is already removed.");
            return true;
        }
        if (count != 1)
        {
            LOG_WARN("[FramePacing] samp.dll: 100 FPS cap check not found uniquely (matches: {}), left as is.", count);
            return false;
        }

        uint8_t* jump = found + kJumpOffset;
        DWORD oldProtect = 0;
        if (!VirtualProtect(jump, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_WARN("[FramePacing] VirtualProtect failed ({}), 100 FPS cap left as is.", GetLastError());
            return false;
        }
        *jump = kJmp;
        DWORD ignored = 0;
        VirtualProtect(jump, 1, oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), jump, 1);

        LOG_INFO("[FramePacing] SA-MP 100 FPS cap removed (samp.dll+0x{:X}).",
                 static_cast<unsigned>(jump - reinterpret_cast<uint8_t*>(samp)));
        return true;
    }

    void SetFrameLimit(int fps)
    {
        if (fps != 0 && fps < kMinFps)
            fps = kMinFps;
        if (fps > kMaxFps)
            fps = 0;
        g_limitFps.store(fps, std::memory_order_release);
        if (fps > 0)
            LOG_INFO("[FramePacing] Frame limit: {} FPS (applies while the game Frame Limiter is off).", fps);
        else
            LOG_INFO("[FramePacing] Frame limit: none (unlimited).");
    }

    void OnPresent()
    {
        const int fps = g_limitFps.load(std::memory_order_acquire);
        if (fps <= 0 || *reinterpret_cast<volatile uint8_t*>(kFrameLimiterFlag) != 0)
        {
            g_last = 0;
            return;
        }
        if (g_freq.QuadPart == 0)
            QueryPerformanceFrequency(&g_freq);

        const int64_t interval = g_freq.QuadPart / fps;
        const int64_t now = Now();
        if (g_last == 0 || now - g_last > 4 * interval)
        {
            g_last = now; // первый кадр или долгая пауза (загрузка, сворачивание) — без догоняния
            return;
        }
        const int64_t target = g_last + interval;
        if (now < target)
            WaitUntil(target);
        // Без накопления долга: если кадр опоздал больше чем на интервал, отсчёт заново.
        g_last = (Now() - target > interval) ? Now() : target;
    }
}
