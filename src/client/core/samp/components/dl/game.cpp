#include "game.hpp"

// Primorsk: addresses only; readiness checks live in SampGameView (game_view.cpp).
GameView_DL::GameView_DL()
    : SampGameView("DL", 0x2ACA3C, 0xA0530, 0xA0410, 0)
{
}
