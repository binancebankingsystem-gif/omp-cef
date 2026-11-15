#pragma once

#include <cstdint>

class IGameView 
{
public:
    virtual ~IGameView() = default;

    virtual void SetCursorMode(int mode, bool hideCursorImmediately) = 0;
    virtual void ProcessInputEnabling() = 0;
};

// Primorsk: shared implementation for all SA:MP versions.
// Crash 15.11-16.11 (samp.dll+0xA06D1, App::Tick -> FocusManager::Update): CGame::ProcessInputEnabling does
// `mov eax,[pD3DDevice]; mov ecx,[eax]; call [ecx+0x30]` (IDirect3DDevice9::ShowCursor). While SA:MP is still
// loading, its device pointer is null, and the CGame pointer was cached once in the constructor (before SA:MP init).
// Now: CGame pointer is read on every call, and SA:MP's own device pointer must be non-null before any call.
class SampGameView : public IGameView
{
public:
    // gameSlotRva - global CGame* in samp.dll; deviceSlotRva - SA:MP's IDirect3DDevice9* (0 - find it in the
    // ProcessInputEnabling code by the `A1 <addr> 8B 08 57 50 FF 51 30` pattern).
    SampGameView(const char* version, uintptr_t gameSlotRva, uintptr_t setCursorRva, uintptr_t processInputRva, uintptr_t deviceSlotRva);

    void SetCursorMode(int mode, bool hideCursorImmediately) override;
    void ProcessInputEnabling() override;

private:
    void* Ready();   // CGame* when SA:MP is ready, otherwise nullptr (logged once per wait)

    const char* version_ = "";
    void** game_slot_ = nullptr;
    void** device_slot_ = nullptr;
    void* set_cursor_fn_ = nullptr;
    void* process_input_enable_fn_ = nullptr;
    bool waiting_logged_ = false;
};
