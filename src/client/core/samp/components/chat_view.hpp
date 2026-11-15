#pragma once

class IChatView
{
public:
    virtual ~IChatView() = default;

    // Primorsk: true - chat cleared; false - SA:MP chat is not ready yet (CChat or its DXUT controls
    // are not created: UpdateScrollbar on a null m_pScrollbar crashed at samp.dll+0xA06D1), caller retries later.
    virtual bool Clear() = 0;
};
