#pragma once

#include <windows.h>

// Primorsk: запись падений в Documents\GTA San Andreas User Files\cef\crash.log (см. crash_diag.cpp).
void CrashDiag_Install(HMODULE self);
void CrashDiag_Uninstall();
