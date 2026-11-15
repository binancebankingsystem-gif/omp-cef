#include "game.hpp"

// Primorsk: addresses only; readiness checks live in SampGameView (game_view.cpp).
GameView_R1::GameView_R1()
    : SampGameView("R1", 0x21A10C, 0x9BD30, 0x9BC10, 0)
{
}
