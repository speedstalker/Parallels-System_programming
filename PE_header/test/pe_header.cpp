#include "pe_header.h"

#include "stdafx.h"
#include <stdio.h>


void print_help (char** argv)
{
printf("\n");
printf("USAGE: %s [options]\n", argv[0]);
printf("\n");
printf("options:\n");
printf("-?                  : print this help\n");
printf("-o <filename>       : print program output to file\n");
printf("-f <path_to_exe/dll>: .exe/.dll file to parse, DEFAULT=%s\n", argv[0]);
printf("-p <path_to_pdb>    : .pdb file to parse\n");
}


//=============================================================================
// Create file mapping
//-----------------------------------------------------------------------------
int MapExecutableFile (const char* file_name, PVOID* ppImageBase)
{
if ((file_name == NULL) || (ppImageBase == NULL))
    {
    // printf ("MapExecutableFile: NULL ptr was passed as a parameter");
    SetLastError (ERROR_BAD_ARGUMENTS);
    return -1;
    }

HANDLE hFile = CreateFile (file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (hFile == INVALID_HANDLE_VALUE)
    {
    // printf ("MapExecutableFile: CreateFile: failed to open %s with error %d\n", file_name, GetLastError());
    return -2;
    }

HANDLE hFileMapping = CreateFileMapping (hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
if (hFileMapping == INVALID_HANDLE_VALUE)
    {
    CloseHandle (hFile);

    // printf("MapExecutableFile: CreateFileMapping: failed with error %d\n", GetLastError());
    return -3;
    }

*ppImageBase = MapViewOfFile (hFileMapping, FILE_MAP_READ, 0, 0, 0);
if (ppImageBase == NULL)
    {
    CloseHandle (hFileMapping);
    CloseHandle (hFile);

    // printf("MapExecutableFile: MapViewOfFile: failed with error %d\n", GetLastError());
    return -4;
    }

CloseHandle (hFileMapping);
CloseHandle (hFile);

return 0;
}
//=============================================================================


//=============================================================================
// DOS and PE header
//-----------------------------------------------------------------------------
int DumpDosAndPeMagics (const PVOID pImageBase)
{
if (pImageBase == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return -1;
    }

PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
printf ("DOS HEADER: magic = %c%c\n", pDosHeader->e_magic & 0xFF, (pDosHeader->e_magic >> 8) & 0xFF);

PIMAGE_NT_HEADERS pPeHeader  = (PIMAGE_NT_HEADERS)(((ULONG_PTR)pImageBase) + pDosHeader->e_lfanew);
printf ("PE HEADER: magic = %c%c%x%x, rva = 0x%x\n", 
    (pPeHeader->Signature)       & 0xFF,
    (pPeHeader->Signature >> 8)  & 0xFF,
    (pPeHeader->Signature >> 16) & 0xFF,
    (pPeHeader->Signature >> 24) & 0xFF,
    pDosHeader->e_lfanew);

return 0;
}

Supported_machines_t GetBitnessOfExecutable (const PIMAGE_NT_HEADERS pPeHeader)
{
if (pPeHeader == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return MACHINE_UNKNOWN;
    }

switch (pPeHeader->FileHeader.Machine)
    {
    case MACHINE_I386:  return MACHINE_I386;
    case MACHINE_AMD64: return MACHINE_AMD64;

    default: return MACHINE_UNKNOWN;
    }

SetLastError (ERROR_INVALID_DATA);
return MACHINE_UNKNOWN;
}

int DumpListOfSections (const PIMAGE_NT_HEADERS pPeHeader)
{
if (pPeHeader == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return -1;
    }

PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(((ULONG_PTR)pPeHeader) +
                                        sizeof (DWORD) +
                                        sizeof (IMAGE_FILE_HEADER) +
                                        pPeHeader->FileHeader.SizeOfOptionalHeader);

printf ("List of sections:\n\n");
for (int i = 0; i < pPeHeader->FileHeader.NumberOfSections; i++)
    {
    printf ("\t%8s \n", (pSectionHeader++)->Name);
    }

return 0;
}
//=============================================================================


//=============================================================================
// Import table
//-----------------------------------------------------------------------------
template <typename PIMAGE_NT_HEADERS_T, typename PIMAGE_THUNK_DATA_T, typename IMAGE_ORDINAL_FLAG_T>
int DumpImportTable (const PVOID pImageBase, const PIMAGE_NT_HEADERS_T pPeHeader, IMAGE_ORDINAL_FLAG_T IMAGE_ORDINAL_FLAG_VALUE)
{
if (pPeHeader == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return ERROR_BAD_ARGUMENTS;
    }

printf ("Size of ImportTable: %d \n\n", pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
    {
    // printf ("%s does not have Import table\n", file_name);
    SetLastError (ERROR_NO_MORE_ITEMS);
    return ERROR_NO_MORE_ITEMS;
    }
else
    {
    while (pImportTable->Characteristics)
        {
        // printf("\n");
        printf ("Imported DLL name: %s \n", (char*)(pImportTable->Name + (ULONG_PTR)pImageBase));
        printf("\n");

        PIMAGE_THUNK_DATA_T pThunk = (PIMAGE_THUNK_DATA_T)(pImportTable->OriginalFirstThunk + (ULONG_PTR)pImageBase);
        if (pImportTable->OriginalFirstThunk == 0)
            pThunk = (PIMAGE_THUNK_DATA_T)(pImportTable->FirstThunk + (ULONG_PTR)pImageBase);

        while (pThunk->u1.AddressOfData)
            {
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG_VALUE)
                {
                // printf ("\t func ordinal: %lld\n", pThunk->u1.Ordinal & (~IMAGE_ORDINAL_FLAG_VALUE));
                // this is all to avoid warning about wrong format specifier in 'printf' for different architectures (%ld and %lld) 
                char  ld_str[] = "\t func ordinal: %ld\n";
                char lld_str[] = "\t func ordinal: %lld\n";
                char fmt_str[sizeof (lld_str) + 1] = {0};
                if (IMAGE_ORDINAL_FLAG_VALUE == IMAGE_ORDINAL_FLAG64)
                    strcpy_s (fmt_str, sizeof (fmt_str), lld_str);
                else
                    strcpy_s (fmt_str, sizeof (fmt_str), ld_str);

                printf (fmt_str, pThunk->u1.Ordinal & (~IMAGE_ORDINAL_FLAG_VALUE));
                }
            else
                {
                printf("\t func hint: %d, name: %s \n",
                        ((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + (ULONG_PTR)pImageBase))->Hint,
                        ((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + (ULONG_PTR)pImageBase))->Name);
                }

            printf("\n");

            pThunk++;
            }

        pImportTable++;
        }
    }

return 0;
}
//-----------------------------------------------------------------------------
// Explicit instantiation
//-----------------------------------------------------------------------------
// for x64
template int DumpImportTable
<PIMAGE_NT_HEADERS64, PIMAGE_THUNK_DATA64, ULONGLONG> (const PVOID pImageBase, const PIMAGE_NT_HEADERS64 pPeHeader, ULONGLONG IMAGE_ORDINAL_FLAG_VALUE);

//for x86
template int DumpImportTable
<PIMAGE_NT_HEADERS32, PIMAGE_THUNK_DATA32, DWORD> (const PVOID pImageBase, const PIMAGE_NT_HEADERS32 pPeHeader, DWORD IMAGE_ORDINAL_FLAG_VALUE);
//=============================================================================


//=============================================================================
// Export table
//-----------------------------------------------------------------------------
template <typename PIMAGE_NT_HEADERS_T>
int DumpExportTable (const PVOID pImageBase, const PIMAGE_NT_HEADERS_T pPeHeader)
{
if (pPeHeader == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return ERROR_BAD_ARGUMENTS;
    }

PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
    {
    // printf("%s does not have Export table\n\n", file_name);
    SetLastError (ERROR_NO_MORE_ITEMS);
    return ERROR_NO_MORE_ITEMS;
    }
else
    {
    printf("Name of DLL, export table comes from: %s \n\n", (char*)(pExportTable->Name + (ULONG_PTR)pImageBase));

    DWORD base_to_add = pExportTable->Base;
    printf ("Base of Ordinals: %d\n", base_to_add);

    DWORD numb_of_entries = pExportTable->NumberOfFunctions;
    printf("Number of functions: %d\n", numb_of_entries);
    if (pExportTable->NumberOfFunctions > pExportTable->NumberOfNames)
        {
        numb_of_entries = pExportTable->NumberOfNames;
        printf("Number of names: %d\n", numb_of_entries);
        }
    printf ("Number of entries: %d\n\n", numb_of_entries);

    DWORD* pAddressOfFunctions =   (DWORD*)(pExportTable->AddressOfFunctions    + (ULONG_PTR)pImageBase);
    WORD*  pAddressOfNameOrdinals = (WORD*)(pExportTable->AddressOfNameOrdinals + (ULONG_PTR)pImageBase);
    DWORD* pAddressOfNames =       (DWORD*)(pExportTable->AddressOfNames        + (ULONG_PTR)pImageBase);

    printf ("RVA \t\t Ordinal \t Name\n");
    for (size_t i = 0; i < numb_of_entries; i++)
        {
        printf ("%8x \t %d \t %s\n", pAddressOfFunctions[pAddressOfNameOrdinals[i]],
                                     pAddressOfNameOrdinals[i] + base_to_add,
                                     (char*)(pAddressOfNames[i] + (ULONG_PTR)pImageBase));
        }
    }

return 0;
}
//-----------------------------------------------------------------------------
// Explicit instantiation
//-----------------------------------------------------------------------------
// for x64
template int DumpExportTable
<PIMAGE_NT_HEADERS64> (const PVOID pImageBase, const PIMAGE_NT_HEADERS64 pPeHeader);

//for x86
template int DumpExportTable
<PIMAGE_NT_HEADERS32> (const PVOID pImageBase, const PIMAGE_NT_HEADERS32 pPeHeader);
//=============================================================================


//=============================================================================
// PDB matching
//-----------------------------------------------------------------------------
// extract expected GUIDs from exe/dll
//-----------------------------------------------------------------------------
int DumpAndGetExpected_GUID_Age_PdbFileName (
        const PVOID pImageBase,
        const PIMAGE_NT_HEADERS pPeHeader,
        
        DWORD* pExpectedSignature,
        GUID*  pExpectedGUID,
        DWORD* pExpectedAge,
        BYTE** pExpectedPdbFileName)
{
if (pPeHeader == NULL)
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return ERROR_BAD_ARGUMENTS;
    }

PIMAGE_DEBUG_DIRECTORY pDebugSection = (PIMAGE_DEBUG_DIRECTORY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
PIMAGE_DEBUG_DIRECTORY pDebugDir = pDebugSection;

if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == NULL)
    {
    // printf("%s does not have Debug directory\n\n", file_name);
    SetLastError (ERROR_NO_MORE_ITEMS);
    return ERROR_NO_MORE_ITEMS;
    }
else
    {
    size_t DebugSectionSize = pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    size_t NumbOfDebugDirs = DebugSectionSize / sizeof(IMAGE_DEBUG_DIRECTORY);
    printf ("Debug section: size = %zu, NumbOfDebugDirs = %zu %s\n\n", DebugSectionSize, NumbOfDebugDirs,
        (sizeof (IMAGE_DEBUG_DIRECTORY) * NumbOfDebugDirs == DebugSectionSize) ? "" : "BAD");
    if (sizeof (IMAGE_DEBUG_DIRECTORY) * NumbOfDebugDirs != DebugSectionSize) // checksum, kinda...
        {
        SetLastError (ERROR_DATA_CHECKSUM_ERROR);
        return ERROR_DATA_CHECKSUM_ERROR;
        }

    for (int i = 0; i < NumbOfDebugDirs; i++)
        {
        if (pDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
            {
            printf ("IMAGE_DEBUG_TYPE_CODEVIEW DebugDir has been found.\n\n");
            break;
            }
        else if (i == NumbOfDebugDirs - 1)
            {
            pDebugDir = NULL;
            break;
            }

        pDebugDir++;
        }

    if (pDebugDir != NULL)
        {
        ULONG_PTR CvInfo = pDebugDir->AddressOfRawData + (ULONG_PTR)pImageBase;

        if ((((PCV_INFO_PDB20)CvInfo)->CvHeader.CvSignature & 0xFF) == 'N') // NB10
            {
            if (pExpectedSignature != NULL)
                *pExpectedSignature = ((PCV_INFO_PDB20)CvInfo)->Signature;

            if (pExpectedAge != NULL)
                *pExpectedAge = ((PCV_INFO_PDB20)CvInfo)->Age;

            if (pExpectedPdbFileName != NULL)
                *pExpectedPdbFileName = ((PCV_INFO_PDB20)CvInfo)->PdbFileName;

            printf ("CV_INFO_PDB20: ExpectedSignature: %u\n", *pExpectedSignature);
            printf ("               ExpectedAge: %u\n", *pExpectedAge);
            printf ("               ExpectedPdbFileName: %s\n", *pExpectedPdbFileName);
            }
        else if ((((PCV_INFO_PDB70)CvInfo)->CvSignature & 0xFF) == 'R') // RSDS
            {
            if (pExpectedGUID != NULL)
                *pExpectedGUID = ((PCV_INFO_PDB70)CvInfo)->Signature;

            if (pExpectedAge != NULL)
                *pExpectedAge = ((PCV_INFO_PDB70)CvInfo)->Age;

            if (pExpectedPdbFileName != NULL)
                *pExpectedPdbFileName = ((PCV_INFO_PDB70)CvInfo)->PdbFileName;

            printf ("CV_INFO_PDB70: ExpectedGUIDSignature: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n", (*pExpectedGUID).Data1, (*pExpectedGUID).Data2, (*pExpectedGUID).Data3,
                (*pExpectedGUID).Data4[0], (*pExpectedGUID).Data4[1], (*pExpectedGUID).Data4[2], (*pExpectedGUID).Data4[3], (*pExpectedGUID).Data4[4], (*pExpectedGUID).Data4[5], (*pExpectedGUID).Data4[6], (*pExpectedGUID).Data4[7]);

            printf ("               ExpectedAge: %u\n", *pExpectedAge);
            printf ("               ExpectedPdbFileName: %s\n", *pExpectedPdbFileName);
            }
        else
            {
            printf ("Unknown size of CV_INFO_PDBXX\n");
            SetLastError (ERROR_INVALID_DATA);
            return ERROR_INVALID_DATA;
            }
        }
    }

return 0;
}
//=============================================================================


//=============================================================================
// .pdata and .xdata
//-----------------------------------------------------------------------------
int DumpPdataXdata (const PVOID pImageBase, const PIMAGE_NT_HEADERS pPeHeader, const Name_addr_map_ptr pFuncAddrNameMap)
{
if ((pPeHeader == NULL) || (pFuncAddrNameMap == NULL))
    {
    SetLastError (ERROR_BAD_ARGUMENTS);
    return ERROR_BAD_ARGUMENTS;
    }

PIMAGE_RUNTIME_FUNCTION_ENTRY pPdataSection = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncEntry = pPdataSection;

if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == NULL)
    {
    // printf("%s does not have .pdata section\n\n", file_name);
    SetLastError (ERROR_NO_MORE_ITEMS);
    return ERROR_NO_MORE_ITEMS;
    }

else
    {
    size_t PdataSectionSize = pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    size_t NumbOfRuntimeFuncStructs = PdataSectionSize / sizeof (IMAGE_RUNTIME_FUNCTION_ENTRY);

    printf (".pdata section: size = %zu, NumbOfRuntimeFuncStructs = %zu %s\n\n", PdataSectionSize, NumbOfRuntimeFuncStructs,
                            (sizeof (IMAGE_RUNTIME_FUNCTION_ENTRY) * NumbOfRuntimeFuncStructs == PdataSectionSize) ? "" : "BAD");
    if (sizeof (IMAGE_RUNTIME_FUNCTION_ENTRY) * NumbOfRuntimeFuncStructs != PdataSectionSize) // checksum, kinda...
        {
        SetLastError (ERROR_DATA_CHECKSUM_ERROR);
        return ERROR_DATA_CHECKSUM_ERROR;
        }
    
    printf ("pImageBase = %p\n\n", (void*)pImageBase);
    for (size_t i = 0; i < NumbOfRuntimeFuncStructs; i++)
        {
        printf ("#%zd RUNTIME_FUNCTION: ", i + 1);

        Name_addr_map_t::const_iterator got = pFuncAddrNameMap->find((ULONG_PTR)(pRuntimeFuncEntry->BeginAddress));
        if (got != pFuncAddrNameMap->end())
            std::wcout << got->second << std::endl;
        else
            std::wcout << std::endl;

        printf (" BeginAddress = %p,\n", (void*)(ULONG_PTR)(pRuntimeFuncEntry->BeginAddress));
        printf (" EndAddress   = %p,\n", (void*)(ULONG_PTR)(pRuntimeFuncEntry->EndAddress));


        if (((pRuntimeFuncEntry->UnwindInfoAddress) & 1) == 0)
            {
            printf(" UnwindInfoAddress = %p\n", (void*)(ULONG_PTR)(pRuntimeFuncEntry->UnwindInfoAddress));
            
            PUNWIND_INFO UnwindInfoAddress = (PUNWIND_INFO)(pRuntimeFuncEntry->UnwindInfoAddress + (ULONG_PTR)pImageBase);
            printf ("\t version = %d %s\n", UnwindInfoAddress->Version, (UnwindInfoAddress->Version == 1) ? "" : "BAD\n");
            if (UnwindInfoAddress->Version != 1)
                continue;

            BYTE is_UNW_FLAG_EHANDLER_set = (UnwindInfoAddress->Flags & UNW_FLAG_EHANDLER);
            BYTE is_UNW_FLAG_UHANDLER_set = (UnwindInfoAddress->Flags & UNW_FLAG_UHANDLER);
            BYTE is_UNW_FLAG_CHAININFO_set = (UnwindInfoAddress->Flags & UNW_FLAG_CHAININFO);
            printf ("\t flags: %s %s %s\n", (is_UNW_FLAG_EHANDLER_set)  ? "UNW_FLAG_EHANDLER"  : "",
                                            (is_UNW_FLAG_UHANDLER_set)  ? "UNW_FLAG_UHANDLER"  : "",
                                            (is_UNW_FLAG_CHAININFO_set) ? "UNW_FLAG_CHAININFO" : "");

            // Get the address of 'UNWIND_INFO.Variable', NOTE: 'UnwindCode' has even number on elements
            // msdn: "For alignment purposes, this array will always have an even number of entries, with the final entry potentially unused."
            PVariable pUNWIND_INFO_Variable = (PVariable)(&(UnwindInfoAddress->UnwindCode[(UnwindInfoAddress->CountOfCodes + 1) & ~1]));
            if (is_UNW_FLAG_EHANDLER_set || is_UNW_FLAG_UHANDLER_set)
                {
                printf("\t Address of %s handler = %p, ", is_UNW_FLAG_EHANDLER_set ? "exception" : "termination", (void*)(ULONG_PTR)(pUNWIND_INFO_Variable->ExceptionHandlerInfo.pExceptionHandler));
                
                Name_addr_map_t::const_iterator got = pFuncAddrNameMap->find((ULONG_PTR)(pUNWIND_INFO_Variable->ExceptionHandlerInfo.pExceptionHandler));
                if (got != pFuncAddrNameMap->end())
                    {
                    printf("name of %s handler: ", is_UNW_FLAG_EHANDLER_set ? "exception" : "termination");
                    std::wcout << got->second << std::endl;
                    }
                else
                    std::wcout << std::endl;
                }
            else if (is_UNW_FLAG_CHAININFO_set)
                printf("\t another 'Chained Unwind Info' is here\n");
            
            printf("\t size of prolog = %d\n", UnwindInfoAddress->SizeOfProlog);
            printf("\t count of unwind codes = %d\n", UnwindInfoAddress->CountOfCodes);
            printf("\t frame register = %d\n", UnwindInfoAddress->FrameRegister);
            printf("\t frame offset = %d\n", UnwindInfoAddress->FrameOffset);

            for (int i = 0; i < UnwindInfoAddress->CountOfCodes; i++)
                {
                printf ("\t\t #%d UNWIND_CODE: offset in prolog = %d\n", i, UnwindInfoAddress->UnwindCode[i].CodeOffset);
                
                printf ("\t\t                 unwind operation code = %d : ", UnwindInfoAddress->UnwindCode[i].UnwindOp);
                switch (UnwindInfoAddress->UnwindCode[i].UnwindOp)
                    {
                    case UWOP_PUSH_NONVOL    : printf("UWOP_PUSH_NONVOL\n");     break;
                    case UWOP_ALLOC_LARGE    : printf("UWOP_ALLOC_LARGE\n");     break;
                    case UWOP_ALLOC_SMALL    : printf("UWOP_ALLOC_SMALL\n");     break;
                    case UWOP_SET_FPREG      : printf("UWOP_SET_FPREG\n");       break;
                    case UWOP_SAVE_NONVOL    : printf("UWOP_SAVE_NONVOL\n");     break;
                    case UWOP_SAVE_NONVOL_FAR: printf("UWOP_SAVE_NONVOL_FAR\n"); break;
                    case UWOP_SAVE_XMM128    : printf("UWOP_SAVE_XMM128\n");     break;
                    case UWOP_SAVE_XMM128_FAR: printf("UWOP_SAVE_XMM128_FAR\n"); break;
                    case UWOP_PUSH_MACHFRAME : printf("UWOP_PUSH_MACHFRAME\n");  break;

                    default: printf ("Unknown 'UnwindOp'");
                    }
                
                printf ("\t\t                 operation info = %d\n", UnwindInfoAddress->UnwindCode[i].OpInfo);                
                }
                
            }
        else
            printf(" UnwindData = %p\n", (void*)(ULONG_PTR)(pRuntimeFuncEntry->UnwindData));

        printf ("\n");
        pRuntimeFuncEntry++;
        }
    }

return 0;
}
//=============================================================================
