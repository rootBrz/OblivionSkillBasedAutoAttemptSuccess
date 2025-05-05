#include "utils.h"
#include "main.h"
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <psapi.h>

// Find memory address based on pattern
uintptr_t FindPattern(const char *pat)
{
  size_t patLen = (strlen(pat) + 1) / 3;
  unsigned char *patBytes = (unsigned char *)_alloca(patLen);
  unsigned char *mask = (unsigned char *)_alloca(patLen);

  for (size_t i = 0; i < patLen; ++i)
  {
    const char *p = pat + i * 3;
    bool isWildcard = (*p == '?');

    patBytes[i] = isWildcard ? 0x00 : (unsigned char)strtoul(p, nullptr, 16);
    mask[i] = isWildcard ? 0 : 1;
  }

  HMODULE hMod = GetModuleHandle(NULL);
  MODULEINFO mi;
  GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi));
  unsigned char *base = (unsigned char *)hMod;
  size_t max = mi.SizeOfImage - patLen;

  for (size_t i = 0; i <= max; i++)
  {
    if (base[i] != patBytes[0])
      continue;

    bool found = true;

    for (size_t j = 0; j < patLen; j++)
      if (mask[j] && base[i + j] != patBytes[j])
      {
        found = false;
        break;
      }

    if (found)
      return (uintptr_t)base + i;
  }

  return 0;
}
