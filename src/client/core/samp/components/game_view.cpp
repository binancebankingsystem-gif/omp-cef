#include "game_view.hpp"

#include <cstring>
#include <windows.h>

#include "samp/addresses.hpp"
#include "system/logger.hpp"

namespace
{
    // `mov eax,[imm32]; mov ecx,[eax]; push edi; push eax; call [ecx+0x30]` inside CGame::ProcessInputEnabling.
    void** FindDeviceSlot(const uint8_t* fn)
    {
        static const uint8_t tail[] = { 0x8B, 0x08, 0x57, 0x50, 0xFF, 0x51, 0x30 };
        if (!fn)
            return nullptr;
        for (int i = 0; i < 0x200; ++i)
        {
            if (fn[i] == 0xA1 && std::memcmp(fn + i + 5, tail, sizeof(tail)) == 0)
            {
                void** slot = nullptr;
                std::memcpy(&slot, fn + i + 1, sizeof(slot));
                return slot;
            }
        }
        return nullptr;
    }
}

SampGameView::SampGameView(const char* version, uintptr_t gameSlotRva, uintptr_t setCursorRva, uintptr_t processInputRva, uintptr_t deviceSlotRva)
    : version_(version)
{
    auto* base = SampAddresses::Instance().Base();
    if (!base)
    {
        LOG_ERROR("[GameView {}] samp.dll base address is unknown - cursor/input calls disabled.", version_);
        return;
    }

    game_slot_ = reinterpret_cast<void**>(base + gameSlotRva);
    set_cursor_fn_ = base + setCursorRva;
    process_input_enable_fn_ = base + processInputRva;

    void** found = FindDeviceSlot(static_cast<const uint8_t*>(process_input_enable_fn_));
    device_slot_ = deviceSlotRva ? reinterpret_cast<void**>(base + deviceSlotRva) : found;

    if (!device_slot_)
        LOG_ERROR("[GameView {}] SA:MP device pointer not found - cursor/input calls disabled.", version_);
    else if (found && found != device_slot_)
        LOG_WARN("[GameView {}] device pointer by pattern differs from the table ({} vs {}), table used.",
            version_, static_cast<void*>(found), static_cast<void*>(device_slot_));
    else
        LOG_INFO("[GameView {}] SA:MP device pointer at samp.dll+0x{:X}.", version_,
            static_cast<unsigned>(reinterpret_cast<uint8_t*>(device_slot_) - base));
}

void* SampGameView::Ready()
{
    void* game = game_slot_ ? *game_slot_ : nullptr;
    const bool ready = game && device_slot_ && *device_slot_ && set_cursor_fn_ && process_input_enable_fn_;
    if (!ready)
    {
        if (!waiting_logged_)
        {
            waiting_logged_ = true;
            LOG_WARN("[GameView {}] SA:MP is not ready yet (CGame {}, device {}) - cursor/input call skipped.",
                version_, game ? "ok" : "null", (device_slot_ && *device_slot_) ? "ok" : "null");
        }
        return nullptr;
    }
    if (waiting_logged_)
    {
        waiting_logged_ = false;
        LOG_INFO("[GameView {}] SA:MP is ready - cursor/input calls enabled.", version_);
    }
    return game;
}

void SampGameView::SetCursorMode(int mode, bool hideCursorImmediately)
{
    void* game = Ready();
    if (!game)
        return;

    using Fn = void(__thiscall*)(void*, int, int);
    reinterpret_cast<Fn>(set_cursor_fn_)(game, mode, hideCursorImmediately);
}

void SampGameView::ProcessInputEnabling()
{
    void* game = Ready();
    if (!game)
        return;

    using Fn = void(__thiscall*)(void*);
    reinterpret_cast<Fn>(process_input_enable_fn_)(game);
}
