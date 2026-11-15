#pragma once

// Primorsk: частота кадров игры.
// 1) Снимает встроенный предел SA:MP 100 к/с (действует при выключенном Frame Limiter игры).
// 2) Свой ограничитель кадров: предел задаёт лаунчер ключом "fps_limit" в cef/config.json
//    (0 — без предела; ключа нет — поведение SA:MP не меняется).

#include <windows.h>

namespace frame_pacing
{
    // Ищет в samp.dll проверку «Frame Limiter выключен → кадр не короче 10 мс» и отключает её.
    // Работает по образцу байтов (найден в 0.3.7 R1–R5 и 0.3.DL-R1, по одному совпадению).
    // true — предел снят (или уже был снят).
    bool UnlockSampFrameCap(HMODULE samp);

    // Предел кадров в секунду; 0 — без предела. Действует только при выключенном Frame Limiter игры:
    // при включённом кадры держит ограничитель SA:MP (/fpslimit 20–90).
    void SetFrameLimit(int fps);

    // Вызывать на каждом Present игры (до оригинального Present).
    void OnPresent();
}
