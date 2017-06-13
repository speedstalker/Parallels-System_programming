#pragma once


#include <windows.h>

#include <string>
#include <unordered_map>


extern DWORD g_dwMachineType;
typedef std::unordered_map<ULONG_PTR, std::wstring>  Name_addr_map_t;
typedef std::unordered_map<ULONG_PTR, std::wstring>* Name_addr_map_ptr;


bool LoadAndValidateDataFromPdbFile (
    const wchar_t    *szFilename,
    IDiaDataSource  **ppSource,
    IDiaSession     **ppSession,
    IDiaSymbol      **ppGlobal,
    GUID*           ExpectedGUID,
    DWORD           ExpectedSignature,
    DWORD           ExpectedAge);

void AddSymbolToMap (IDiaSymbol *pSymbol, Name_addr_map_t* pFuncAddrNameMap);
bool DumpAllPublicsToMap (IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap);
bool DumpAllGlobalsToMap (IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap);

int CleanupSymbols (IDiaSymbol** pg_pGlobalSymbol, IDiaSession** pg_pDiaSession);
