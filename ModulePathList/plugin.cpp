#include "plugin.h"
#include "pluginsdk/_scriptapi_symbol.h"

#pragma comment(lib, "Dbghelp.lib")

void DebugSymFromAddrFailure(HANDLE hProcess, duint targetAddr) {
  DWORD error = GetLastError();
  char msg[512];

  sprintf_s(msg, sizeof(msg),
            "[SymFromAddr] FAILED\n"
            "  Address: 0x%p\n"
            "  GetLastError: %lu (0x%lX)\n",
            (void *)targetAddr, error, error);
  _plugin_logputs(msg);

  BOOL symInit = SymGetOptions() != 0;
  sprintf_s(msg, sizeof(msg),
            "  SymGetOptions: 0x%lX\n"
            "  SymInitialized? %s\n",
            SymGetOptions(), symInit ? "yes" : "no");
  _plugin_logputs(msg);

  char path[MAX_PATH];
  if (SymGetSearchPath(hProcess, path, MAX_PATH)) {
    sprintf_s(msg, sizeof(msg), "  SymSearchPath: %s\n", path);
    _plugin_logputs(msg);
  }

  IMAGEHLP_MODULE64 modInfo = {sizeof(modInfo)};
  if (SymGetModuleInfo64(hProcess, targetAddr, &modInfo)) {
    sprintf_s(msg, sizeof(msg), "  Module: %s\n  ImageName: %s\n  Base: 0x%p\n",
              modInfo.ModuleName, modInfo.ImageName,
              (void *)modInfo.BaseOfImage);
    _plugin_logputs(msg);
  } else {
    _plugin_logputs("  SymGetModuleInfo64 failed.\n");
  }
}

static bool cbCommand(int argc, char *argv[]) {
  using namespace Script;

  BridgeList<Module::ModuleInfo> modules;
  if (!Module::GetList(&modules)) {
    _plugin_logputs("Module::GetList failed...");
    return false;
  }

  char addr[32] = "";
  auto ptr2str = [&addr](duint ptr) {
    sprintf_s(addr, "%p", ptr);
    return addr;
  };

  GuiReferenceInitialize("Modules");
  GuiReferenceAddColumn(sizeof(duint) * 2, "Base");
  GuiReferenceAddColumn(sizeof(duint) * 2, "Size");
  GuiReferenceAddColumn(sizeof(duint) * 2, "Entry");
  GuiReferenceAddColumn(0, "Path");
  GuiReferenceSetRowCount(int(modules.Count()));

  for (int i = 0; i < modules.Count(); i++) {
    auto &mod = modules[i];
    GuiReferenceSetCellContent(i, 0, ptr2str(mod.base));
    GuiReferenceSetCellContent(i, 1, ptr2str(mod.size));
    GuiReferenceSetCellContent(i, 2, ptr2str(mod.entry));
    GuiReferenceSetCellContent(i, 3, mod.path);
  }
  GuiReferenceReloadData();

  return true;
}

char symbuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
static bool get_symbol_info(HANDLE hProcess, duint imm32, char *&modname,
                            char *&symname) {
  DWORD64 displacement = 0;
  PSYMBOL_INFO pSym = (PSYMBOL_INFO)symbuffer;
  pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
  pSym->MaxNameLen = MAX_SYM_NAME;
  if (!SymFromAddr(hProcess, imm32, &displacement, pSym)) {
    _plugin_logputs("SymFromAddr failed...");
    DebugSymFromAddrFailure(hProcess, imm32);
    return false;
  }

  IMAGEHLP_MODULE64 modInfo = {sizeof(modInfo)};
  if (!SymGetModuleInfo64(hProcess, imm32, &modInfo)) {
    _plugin_logputs("SymGetModuleInfo64 failed...");
    DebugSymFromAddrFailure(hProcess, imm32);
    return false;
  }
  symname = pSym->Name;
  modname = modInfo.ModuleName;

  return true;
}

static void fill_table(BridgeList<Script::Symbol::SymbolInfo> symbols,
                       Script::Symbol::SymbolType type) {
  char addr[32] = "";
  auto ptr2str = [&addr](duint ptr) {
    sprintf_s(addr, "%p", ptr);
    return addr;
  };
  auto int2str = [&addr](duint num) {
    _itoa_s(num, addr, 10);
    return addr;
  };

  char buff[64] = "";
  auto symload = [&addr](int num) {
    sprintf_s(addr, "Loaded %i symbols", num);
    return addr;
  };
  _plugin_logputs(symload(symbols.Count()));

  if (type == Script::Symbol::Import)
    GuiReferenceInitialize("ModuleImports");
  else
    GuiReferenceInitialize("ModuleExports");

  GuiReferenceAddColumn(32, "Module");
  GuiReferenceAddColumn(sizeof(duint) * 2, "Address");
  // GuiReferenceAddColumn(sizeof(duint) * 2, "Ordinal");
  GuiReferenceAddColumn(32, "Function");

  if (type == Script::Symbol::Import) {
    GuiReferenceAddColumn(8, "Bytes");
    GuiReferenceAddColumn(32, "Modname");
    GuiReferenceAddColumn(32, "Symname");
  }

  int num_symbols = 0;
  for (int i = 0; i < symbols.Count(); i++) {
    auto &symbol = symbols[i];
    if (symbol.type == type)
      num_symbols++;
  }
  GuiReferenceSetRowCount(num_symbols);
  HANDLE hProcess = DbgGetProcessHandle();
  if (!SymInitialize(hProcess, NULL, TRUE)) {
    char buf[128];
    sprintf_s(buf, "[SymInit] Failed for hProcess=%p err=%lu", hProcess,
              GetLastError());
    _plugin_logputs(buf);
  }
  num_symbols = 0;
  for (int i = 0; i < symbols.Count(); i++) {
    auto &symbol = symbols[i];

    if (symbol.type == type) {
      duint rva = symbol.rva + Script::Module::BaseFromName(symbol.mod);
      // duint ordinal = ImporterGetAPIOrdinalNumber(ULONG_PTR(rva));
      char *name = static_cast<char *>(ImporterGetAPIName(ULONG_PTR(rva)));

      if (type == Script::Symbol::Import) {
        duint targetAddr = 0;
        DbgMemRead(rva, &targetAddr, sizeof(targetAddr));
        GuiReferenceSetCellContent(num_symbols, 3, ptr2str(targetAddr));
        char *symname, *modname;
        if (get_symbol_info(hProcess, targetAddr, modname, symname)) {
          GuiReferenceSetCellContent(num_symbols, 4, modname);
          GuiReferenceSetCellContent(num_symbols, 5, symname);
        }
      }

      GuiReferenceSetCellContent(num_symbols, 0, symbol.mod);
      GuiReferenceSetCellContent(num_symbols, 1, ptr2str(rva));
      // GuiReferenceSetCellContent(num_symbols, 2, int2str(ordinal));
      GuiReferenceSetCellContent(num_symbols, 2, symbol.name);
      num_symbols++;
    }
  }
  GuiReferenceReloadData();
}

static bool cbCommand2(int argc, char *argv[]) {
  using namespace Script;

  BridgeList<Symbol::SymbolInfo> symbols;
  if (!Symbol::GetList(&symbols)) {
    _plugin_logputs("Symbol::GetList failed...");
    return false;
  }

  fill_table(symbols, Symbol::Export);

  return true;
}

static bool cbCommand3(int argc, char *argv[]) {
  using namespace Script;

  BridgeList<Symbol::SymbolInfo> symbols;
  if (!Symbol::GetList(&symbols)) {
    _plugin_logputs("Symbol::GetList failed...");
    return false;
  }

  fill_table(symbols, Symbol::Import);

  return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT *initStruct) {
  if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbCommand, false))
    _plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME
                    "\" command!");

  if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME "Exports", cbCommand2,
                               false))
    _plugin_logputs("[" PLUGIN_NAME "Exports"
                    "] Error registering the \"" PLUGIN_NAME "\" command!");

  if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME "Imports", cbCommand3,
                               false))
    _plugin_logputs("[" PLUGIN_NAME "Imports"
                    "] Error registering the \"" PLUGIN_NAME "\" command!");

  return true; // Return false to cancel loading the plugin.
}

// Deinitialize your plugin data here (clearing menus optional).
bool pluginStop() { return true; }

// Do GUI/Menu related things here.
void pluginSetup() {}
