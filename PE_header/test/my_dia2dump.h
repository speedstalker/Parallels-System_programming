#pragma once

extern DWORD g_dwMachineType;
typedef std::unordered_map<ULONG_PTR, std::wstring> Name_addr_map_t;


bool LoadAndValidateDataFromPdb (
    const wchar_t    *szFilename,
    IDiaDataSource  **ppSource,
    IDiaSession     **ppSession,
    IDiaSymbol      **ppGlobal,
    GUID*           ExpectedGUID,
    DWORD           ExpectedSignature,
    DWORD           ExpectedAge);
void PrintPublicSymbol (IDiaSymbol *pSymbol);
void AddPublicSymbolToMap (IDiaSymbol *pSymbol, Name_addr_map_t* pFuncAddrNameMap);
bool DumpAllPublicsToMap (IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap);
// void Cleanup();