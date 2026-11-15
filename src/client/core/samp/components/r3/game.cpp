#include "game.hpp"

// Primorsk: addresses only; readiness checks live in SampGameView (game_view.cpp).
GameView_R3::GameView_R3()
    : SampGameView("R3", 0x26E8F4, 0x9FFE0, 0x9FEC0, 0)
{
}
