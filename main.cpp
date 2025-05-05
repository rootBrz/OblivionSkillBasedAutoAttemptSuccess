#include "main.h"
#include "MinHook.h"
#include "utils.h"
#include <consoleapi.h>
#include <cstdio>
#include <minwindef.h>
#include <process.h>

extern "C" void *oSecFunc;
extern "C" float playerSecurityLevel;
void *oSecFunc = nullptr;
float playerSecurityLevel = 0.0f;
static void SecHook(void) __attribute__((naked));
static void SecHook(void)
{
  __asm__ volatile(
      ".intel_syntax noprefix\n\t"
      "movss playerSecurityLevel[rip], xmm0\n\t"
      "jmp oSecFunc[rip]\n\t"
      ".att_syntax prefix\n\t"
      :
      :
      : "xmm0", "memory", "cc");
}

extern "C" void *oComFunc;
void *oComFunc = nullptr;
static void ComHook(void) __attribute__((naked));
static void ComHook(void)
{
  __asm__ volatile(
      ".intel_syntax noprefix\n\t"
      "movss xmm1, playerSecurityLevel[rip]\n\t" // Player skill
      "divss xmm1, dword ptr div_const[rip]\n\t" // 25.0
      "addss xmm1, dword ptr add_const[rip]\n\t" // 1.0
      "cvtsi2ss xmm2, dword ptr [rsp+0x20]\n\t"  // Lock level
      "comiss xmm1, xmm2\n\t"                    // Compare (skill/25+1) vs lock level
      "jb no_adjust\n\t"                         // Jump if below (CF=1)
      "xorps xmm0, xmm0\n\t"
      "no_adjust:\n\t"
      "xorps xmm1, xmm1\n\t"
      "xorps xmm2, xmm2\n\t"
      "jmp oComFunc[rip]\n\t"
      "div_const: .long 0x41C80000\n\t" // 25.0 in IEEE 754
      "add_const: .long 0x3F800000\n\t" // 1.0 in IEEE 754
      ".att_syntax prefix\n\t"
      :
      :
      : "xmm0", "xmm1", "xmm2", "memory", "cc");
}

unsigned __stdcall InitThread(void *)
{
  FILE *log = fopen(LOG_NAME, "w");

  void *skillAddr = (void *)FindPattern("F3 0F 10 15 ?? ?? ?? ?? 44 8B C8 F3 0F 10 0D ?? ?? ?? ?? F3 0F 10 05");
  void *compAddr = (void *)FindPattern("0F 2F F0 0F 28 74 24 30 0F 97 C0");

  fprintf(log, "Found security skill address: 0x%p\n", skillAddr);
  fprintf(log, "Found comparison address: 0x%p\n", compAddr);
  fclose(log);

  MH_Initialize();

  MH_CreateHook(skillAddr, (LPVOID)SecHook, &oSecFunc);
  MH_EnableHook(skillAddr);

  MH_CreateHook(compAddr, (LPVOID)ComHook, &oComFunc);
  MH_EnableHook(compAddr);

  _endthreadex(0);
  return 0;
}

// OBSE
extern "C"
{
  OBSEPluginVersionData OBSEPlugin_Version{
      OBSEPluginVersionData::kVersion,
      11,
      "Skill Based Auto Attempt Success",
      "rootBrz",
      OBSEPluginVersionData::kAddressIndependence_Signatures,
      OBSEPluginVersionData::kStructureIndependence_NoStructs,
      {},
      {},
      {},
      {},
      {}};

  bool OBSEPlugin_Load(const OBSEInterface *obse)
  {
    PLUGIN_HANDLE = obse->GetPluginHandle();
    OBSE_MESSAGE = (OBSEMessagingInterface *)obse->QueryInterface(kInterface_Messaging);

    return true;
  }
};
