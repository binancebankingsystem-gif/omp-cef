#include "chat.hpp"

#include <cstring>

sampapi::v037r3::CChat* ChatView_R3::GetChat() const
{
    return sampapi::v037r3::RefChat();
}

bool ChatView_R3::Clear()
{
    auto* chat = GetChat();
    // Primorsk: while SA:MP is loading, CChat exists before its dialog controls; UpdateScrollbar/ScrollToBottom
    // dereference m_pScrollbar and crashed (samp.dll+0xA06D1, App::Tick). Wait until everything is created.
    if (!chat || !chat->m_pGameUi || !chat->m_pScrollbar)
        return false;

    for (int i = 0; i < sampapi::v037r3::CChat::MAX_MESSAGES; ++i)
    {
        std::memset(&chat->m_entry[i], 0, sizeof(chat->m_entry[i]));
    }

    if (chat->m_szLastMessage)
        chat->m_szLastMessage[0] = '\0';

    chat->m_nScrollbarPos = 0;
    chat->m_bRedraw = TRUE;

    chat->UpdateScrollbar();
    chat->ScrollToBottom();
    return true;
}
