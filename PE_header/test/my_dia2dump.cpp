#include "stdafx.h"


// Tags returned by Dia
const wchar_t * const rgTags[] =
{
    L"(SymTagNull)",                     // SymTagNull
    L"Executable (Global)",              // SymTagExe
    L"Compiland",                        // SymTagCompiland
    L"CompilandDetails",                 // SymTagCompilandDetails
    L"CompilandEnv",                     // SymTagCompilandEnv
    L"Function",                         // SymTagFunction
    L"Block",                            // SymTagBlock
    L"Data",                             // SymTagData
    L"Annotation",                       // SymTagAnnotation
    L"Label",                            // SymTagLabel
    L"PublicSymbol",                     // SymTagPublicSymbol
    L"UserDefinedType",                  // SymTagUDT
    L"Enum",                             // SymTagEnum
    L"FunctionType",                     // SymTagFunctionType
    L"PointerType",                      // SymTagPointerType
    L"ArrayType",                        // SymTagArrayType
    L"BaseType",                         // SymTagBaseType
    L"Typedef",                          // SymTagTypedef
    L"BaseClass",                        // SymTagBaseClass
    L"Friend",                           // SymTagFriend
    L"FunctionArgType",                  // SymTagFunctionArgType
    L"FuncDebugStart",                   // SymTagFuncDebugStart
    L"FuncDebugEnd",                     // SymTagFuncDebugEnd
    L"UsingNamespace",                   // SymTagUsingNamespace
    L"VTableShape",                      // SymTagVTableShape
    L"VTable",                           // SymTagVTable
    L"Custom",                           // SymTagCustom
    L"Thunk",                            // SymTagThunk
    L"CustomType",                       // SymTagCustomType
    L"ManagedType",                      // SymTagManagedType
    L"Dimension",                        // SymTagDimension
    L"CallSite",                         // SymTagCallSite
    L"InlineSite",                       // SymTagInlineSite
    L"BaseInterface",                    // SymTagBaseInterface
    L"VectorType",                       // SymTagVectorType
    L"MatrixType",                       // SymTagMatrixType
    L"HLSLType",                         // SymTagHLSLType
    L"Caller",                           // SymTagCaller,
    L"Callee",                           // SymTagCallee,
    L"Export",                           // SymTagExport,
    L"HeapAllocationSite",               // SymTagHeapAllocationSite
    L"CoffGroup",                        // SymTagCoffGroup
};

DWORD g_dwMachineType = CV_CFL_80386;

////////////////////////////////////////////////////////////
// Create an IDiaData source and open a PDB file
//
bool LoadAndValidateDataFromPdb(
    const wchar_t    *szFilename,
    IDiaDataSource  **ppSource,
    IDiaSession     **ppSession,
    IDiaSymbol      **ppGlobal,
    GUID*           ExpectedGUID,
    DWORD           ExpectedSignature,
    DWORD           ExpectedAge)
{
    wchar_t wszExt[MAX_PATH];
    wchar_t *wszSearchPath = L"SRV**\\\\symbols\\symbols"; // Alternate path to search for debug data
    DWORD dwMachType = 0;

    HRESULT hr = CoInitialize(NULL);

    // Obtain access to the provider

    hr = CoCreateInstance(__uuidof(DiaSource),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(IDiaDataSource),
        (void **)ppSource);

    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance failed - HRESULT = %08X\n", hr);

        return false;
    }

    _wsplitpath_s(szFilename, NULL, 0, NULL, 0, NULL, 0, wszExt, MAX_PATH);

    if (!_wcsicmp(wszExt, L".pdb")) {
        // Open and prepare a program database (.pdb) file as a debug data source

        hr = (*ppSource)->loadAndValidateDataFromPdb(szFilename, ExpectedGUID, ExpectedSignature, ExpectedAge);

        if (FAILED(hr)) {
            switch (hr)
            {
            case E_PDB_NOT_FOUND: printf ("Failed to open the .pdb file, or the file has an invalid format.\n"); break;
            case E_PDB_FORMAT:    printf ("Attempted to access a .pdb file with an obsolete format.\n"); break;

            case E_PDB_INVALID_SIG: printf ("Failed to open the .pdb file, 'Signature' does not match.\n"); break;
            case E_PDB_INVALID_AGE: printf ("Failed to open the .pdb file, 'Age' does not match..\n"); break;

            case E_INVALIDARG: printf ("loadAndValidateDataFromPdb failed - Invalid parameter.\n"); break;
            case E_UNEXPECTED: printf ("loadAndValidateDataFromPdb failed - The data source has already been prepared.\n"); break;

            default: wprintf(L"loadAndValidateDataFromPdb failed - HRESULT = %08X\n", hr);
            }

            return false;
        }
    }

    else {
        CCallback callback; // Receives callbacks from the DIA symbol locating procedure,
                            // thus enabling a user interface to report on the progress of
                            // the location attempt. The client application may optionally
                            // provide a reference to its own implementation of this
                            // virtual base class to the IDiaDataSource::loadDataForExe method.
        callback.AddRef();

        // Open and prepare the debug data associated with the executable

        hr = (*ppSource)->loadDataForExe(szFilename, wszSearchPath, &callback);

        if (FAILED(hr)) {
            wprintf(L"loadDataForExe failed - HRESULT = %08X\n", hr);

            return false;
        }
    }

    // Open a session for querying symbols

    hr = (*ppSource)->openSession(ppSession);

    if (FAILED(hr)) {
        wprintf(L"openSession failed - HRESULT = %08X\n", hr);

        return false;
    }

    // Retrieve a reference to the global scope

    hr = (*ppSession)->get_globalScope(ppGlobal);

    if (hr != S_OK) {
        wprintf(L"get_globalScope failed\n");

        return false;
    }

    // Set Machine type for getting correct register names

    if ((*ppGlobal)->get_machineType(&dwMachType) == S_OK) {
        switch (dwMachType) {
        case IMAGE_FILE_MACHINE_I386: g_dwMachineType = CV_CFL_80386; break;
        case IMAGE_FILE_MACHINE_IA64: g_dwMachineType = CV_CFL_IA64; break;
        case IMAGE_FILE_MACHINE_AMD64: g_dwMachineType = CV_CFL_AMD64; break;
        }
    }

    /*
    GUID guid = GUID_NULL;
    if ((*ppGlobal)->get_guid(&guid) == S_OK)
    {
        LPOLESTR lp = NULL;

        if (StringFromCLSID(guid, &lp) == S_OK)
            CoTaskMemFree(lp);
    }
    printf ("GUID: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n", guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    */

    return true;
}


////////////////////////////////////////////////////////////
// Print a public symbol info: name, VA, RVA, SEG:OFF
//
void PrintPublicSymbol(IDiaSymbol *pSymbol)
{
    DWORD dwSymTag;
    DWORD dwRVA;
    DWORD dwSeg;
    DWORD dwOff;
    BSTR bstrName;

    if (pSymbol->get_symTag(&dwSymTag) != S_OK) {
        return;
    }

    if (pSymbol->get_relativeVirtualAddress(&dwRVA) != S_OK) {
        dwRVA = 0xFFFFFFFF;
    }

    pSymbol->get_addressSection(&dwSeg);
    pSymbol->get_addressOffset(&dwOff);

    // wprintf(L"%s: [%08X][%04X:%08X] ", rgTags[dwSymTag], dwRVA, dwSeg, dwOff);
    wprintf(L"%X ", dwRVA);

    if (dwSymTag == SymTagThunk) {
        if (pSymbol->get_name(&bstrName) == S_OK) {
            wprintf(L"%s\n", bstrName);

            SysFreeString(bstrName);
        }

        else {
            if (pSymbol->get_targetRelativeVirtualAddress(&dwRVA) != S_OK) {
                dwRVA = 0xFFFFFFFF;
            }

            pSymbol->get_targetSection(&dwSeg);
            pSymbol->get_targetOffset(&dwOff);

            // wprintf(L"target -> [%08X][%04X:%08X]\n", dwRVA, dwSeg, dwOff);
        }
    }

    else {
        // must be a function or a data symbol

        BSTR bstrUndname;

        if (pSymbol->get_name(&bstrName) == S_OK) {
            if (pSymbol->get_undecoratedName(&bstrUndname) == S_OK) {
                // wprintf(L"%s(%s)\n", bstrName, bstrUndname);
                wprintf(L"%s\n", bstrUndname);

                SysFreeString(bstrUndname);
            }

            else {
                wprintf(L"%s\n", bstrName);
            }

            SysFreeString(bstrName);
        }
    }
}


void AddPublicSymbolToMap(IDiaSymbol *pSymbol, Name_addr_map_t* pFuncAddrNameMap) 
{
    DWORD dwSymTag;
    DWORD dwRVA;
    DWORD dwSeg;
    DWORD dwOff;
    BSTR bstrName;

    ULONG_PTR key;
    std::wstring value;


    if (pSymbol->get_symTag(&dwSymTag) != S_OK) {
        return;
    }

    if (pSymbol->get_relativeVirtualAddress(&dwRVA) != S_OK) {
        dwRVA = 0xFFFFFFFF;
    }

    pSymbol->get_addressSection(&dwSeg);
    pSymbol->get_addressOffset(&dwOff);

    // wprintf(L"%s: [%08X][%04X:%08X] ", rgTags[dwSymTag], dwRVA, dwSeg, dwOff);
    // wprintf(L"%X ", dwRVA);
    key = dwRVA;

    if (dwSymTag == SymTagThunk) {
        if (pSymbol->get_name(&bstrName) == S_OK) {
            // wprintf(L"%s\n", bstrName);
            value = bstrName;
            (*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));

            SysFreeString(bstrName);
        }

        else {
            if (pSymbol->get_targetRelativeVirtualAddress(&dwRVA) != S_OK) {
                dwRVA = 0xFFFFFFFF;
            }

            pSymbol->get_targetSection(&dwSeg);
            pSymbol->get_targetOffset(&dwOff);

            // wprintf(L"target -> [%08X][%04X:%08X]\n", dwRVA, dwSeg, dwOff);
            std::wstring test (L"target ->");
            (*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, test));
        }
    }

    else {
        // must be a function or a data symbol

        BSTR bstrUndname;

        if (pSymbol->get_name(&bstrName) == S_OK) {
            if (pSymbol->get_undecoratedName(&bstrUndname) == S_OK) {
                // wprintf(L"%s(%s)\n", bstrName, bstrUndname);
                // wprintf(L"%s\n", bstrUndname);
                value = bstrUndname;
                (*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));

                SysFreeString(bstrUndname);
            }

            else {
                // wprintf(L"%s\n", bstrName);
                value = bstrName;
                (*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));
            }

            SysFreeString(bstrName);
        }
    }
}


////////////////////////////////////////////////////////////
// Dump all the public symbols - SymTagPublicSymbol
//
bool DumpAllPublicsToMap(IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap)
{
    // Retrieve all the public symbols

    IDiaEnumSymbols *pEnumSymbols;

    if (FAILED(pGlobal->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
        return false;
    }

    IDiaSymbol *pSymbol;
    ULONG celt = 0;

    while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
        // PrintPublicSymbol(pSymbol);
        AddPublicSymbolToMap (pSymbol, pFuncAddrNameMap);

        pSymbol->Release();
    }

    pEnumSymbols->Release();

    return true;
}

/* void Cleanup()
{
    if (g_pGlobalSymbol) {
        g_pGlobalSymbol->Release();
        g_pGlobalSymbol = NULL;
    }

    if (g_pDiaSession) {
        g_pDiaSession->Release();
        g_pDiaSession = NULL;
    }

    CoUninitialize();
} */
