#include "game.hpp"

// Primorsk: addresses only; readiness checks live in SampGameView (game_view.cpp).
GameView_R5::GameView_R5()
    : SampGameView("R5", 0x26EBAC, 0xA06F0, 0xA05D0, 0x26EB40)
{
}
