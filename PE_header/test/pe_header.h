#pragma once


#include "my_dia2dump.h"


#define GET_P_PE_HEADER(pImageBase) ((PIMAGE_NT_HEADERS)(((ULONG_PTR)pImageBase) + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew))


typedef enum Supported_machines
    {
    MACHINE_UNKNOWN = 0,
    MACHINE_I386    = 0x014c,
    MACHINE_AMD64   = 0x8664
    } Supported_machines_t;

Supported_machines_t GetBitnessOfExecutable (const PIMAGE_NT_HEADERS pPeHeader);

void print_help (char** argv);

int MapExecutableFile (const char* file_name, PVOID* ppImageBase);

int DumpDosAndPeMagics (const PVOID pImageBase);
int DumpListOfSections (const PIMAGE_NT_HEADERS pPeHeader);


template <typename PIMAGE_NT_HEADERS_T, typename PIMAGE_THUNK_DATA_T, typename IMAGE_ORDINAL_FLAG_T>
int DumpImportTable (const PVOID pImageBase, const PIMAGE_NT_HEADERS_T pPeHeader, IMAGE_ORDINAL_FLAG_T IMAGE_ORDINAL_FLAG_VALUE);

template <typename PIMAGE_NT_HEADERS_T>
int DumpExportTable (const PVOID pImageBase, const PIMAGE_NT_HEADERS_T pPeHeader);


// Expected params can be 'NULL'
int DumpAndGetExpected_GUID_Age_PdbFileName (
        const PVOID pImageBase,
        const PIMAGE_NT_HEADERS pPeHeader,
        
        DWORD* pExpectedSignature,
        GUID*  pExpectedGUID,
        DWORD* pExpectedAge,
        BYTE** pExpectedPdbFileName);

int DumpPdataXdata (const PVOID pImageBase, const PIMAGE_NT_HEADERS pPeHeader, const Name_addr_map_ptr pFuncAddrNameMap);
