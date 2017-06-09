// test.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include <windows.h>



void print_help (char** argv);

#include <iostream>
template <typename M> void _print(const M& m) {
    std::cout << m.size() << " elements: ";

    for (const auto& p : m) {
        //wprintf (L"(%x, %s)", p.first, p.second);
        std::wcout << "(" << p.first << ", " << p.second << ") ";
    }

    std::cout << std::endl;
}


int main (int argc, char* argv[])
{
//=============================================================================
// Create file mapping
//-----------------------------------------------------------------------------
char* file_name = NULL;
char* pdb_name = NULL;

int is_pdb_provided = 0;
int is_to_file = 0;

int argv_idx_of_file = 0;
int argv_idx_of_pdb  = 0;

FILE* stream;
errno_t err;

if (argc > 1)
    for (int i = 1; i < argc; i++)
        {
        if ((argv[i][0] == '-') && (argv[i][1] == 'o'))
            {
            if ((err = freopen_s(&stream, argv[i + 1], "w", stdout)) != 0)
                fprintf(stdout, "error on freopen\n");
            }
        }

if (argc > 1)
    for (int i = 1; i < argc; i++)
        {
        if ((argv[i][0] == '-') && (argv[i][1] == '?'))
            {
            print_help (argv);
            return 0;
            }

        if ((argv[i][0] == '-') && (argv[i][1] == 'f'))
            {
            argv_idx_of_file = i + 1;
            continue;
            }

        if ((argv[i][0] == '-') && (argv[i][1] == 'p'))
            {
            argv_idx_of_pdb = i + 1;
            continue;
            }
        }

file_name = argv[argv_idx_of_file];
if (argv_idx_of_pdb != 0)
    {
    pdb_name = argv[argv_idx_of_pdb];
    is_pdb_provided = 1;
    }

fprintf (stdout, "file_name: %s\n", file_name);
fprintf (stdout, "pdb_name:  %s\n", pdb_name);

HANDLE hFile = CreateFile (file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (INVALID_HANDLE_VALUE == hFile)
    {
    printf ("failed to open %s with error %d\n", argv[0], GetLastError());
    return 1;
    }

HANDLE hFileMapping = CreateFileMapping (hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
if (hFileMapping == 0)
    {
    CloseHandle (hFile);

    printf("failed to create file mapping %s with error %d\n", argv[0], GetLastError());
    return 2;
    }

PVOID pImageBase = MapViewOfFile (hFileMapping, FILE_MAP_READ, 0, 0, 0);
if (NULL == pImageBase)
    {
    CloseHandle (hFileMapping);
    CloseHandle (hFile);

    printf("failed to map %s with error %d\n", argv[0], GetLastError());
    return 3;
    }

//=============================================================================
// Get PE headers
//-----------------------------------------------------------------------------
printf ("//=============================================================================\n");
printf ("// PE headers\n");
printf ("//-----------------------------------------------------------------------------\n");

PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
printf ("DOS HEADER = %c%c 0x%x\n", pDosHeader->e_magic & 0xFF, (pDosHeader->e_magic >> 8) & 0xFF, pDosHeader->e_lfanew);

PIMAGE_NT_HEADERS pPeHeader = (PIMAGE_NT_HEADERS)(((ULONG_PTR)pImageBase) + pDosHeader->e_lfanew);
printf ("PE HEADER = #%c%c%x%x# 0x%x %s\n", 
    (pPeHeader->Signature)       & 0xFF,
    (pPeHeader->Signature >> 8)  & 0xFF,
    (pPeHeader->Signature >> 16) & 0xFF,
    (pPeHeader->Signature >> 24) & 0xFF,
    pPeHeader->FileHeader.Machine,
    pPeHeader->FileHeader.SizeOfOptionalHeader == sizeof (IMAGE_OPTIONAL_HEADER) ? "OK" : "BAD");

if (pPeHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
    return 0;

PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(((ULONG_PTR)pPeHeader) +
                                        sizeof (DWORD) +
                                        sizeof (IMAGE_FILE_HEADER) +
                                        pPeHeader->FileHeader.SizeOfOptionalHeader);
printf ("\n");
printf ("\n");
printf ("List of sections:\n\n");
for (int i = 0; i < pPeHeader->FileHeader.NumberOfSections; i++)
    {
    printf ("\t%8s \n", (pSectionHeader++)->Name);
    }

printf ("\n");
//=============================================================================
// Import table
//-----------------------------------------------------------------------------
printf ("\n");
printf ("//=============================================================================\n");
printf ("// Import table\n");
printf ("//-----------------------------------------------------------------------------\n");

printf ("Size of ImportTable: %d \n\n", pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == NULL)
    printf ("%s does not have Import table\n", file_name);
else
    {
    while (pImportTable->Characteristics)
        {
        // printf("\n");
        printf ("Imported DLL name: %s \n", (char*)(pImportTable->Name + (ULONG_PTR)pImageBase));
        printf("\n");

        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImportTable->OriginalFirstThunk + (ULONG_PTR)pImageBase);
        if (pImportTable->OriginalFirstThunk == NULL)
            pThunk = (PIMAGE_THUNK_DATA)(pImportTable->FirstThunk + (ULONG_PTR)pImageBase);

        while (pThunk->u1.AddressOfData)
            {
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                printf ("\t func ordinal: %lld\n", pThunk->u1.Ordinal & (~IMAGE_ORDINAL_FLAG32));
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
//=============================================================================
// Export table
//-----------------------------------------------------------------------------
printf ("\n");
printf ("//=============================================================================\n");
printf ("// Export table\n");
printf ("//-----------------------------------------------------------------------------\n");

PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
    printf("%s does not have Export table\n\n", file_name);
else
    {
    printf("Name of DLL, export table comes from: %s \n\n", (char*)(pExportTable->Name + (ULONG_PTR)pImageBase));

    DWORD base_to_add = pExportTable->Base;
    printf ("Base: %d\n", base_to_add);

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
        printf ("%8x \t %d \t %s\n", pAddressOfFunctions[i],
                                     pAddressOfNameOrdinals[i] + base_to_add,
                                     (char*)(pAddressOfNames[i] + (ULONG_PTR)pImageBase));
        }
    }
//=============================================================================
// PDB matching
//-----------------------------------------------------------------------------
// extract expected GUIDs from exe/dll
//-----------------------------------------------------------------------------
printf("\n");
printf("//=============================================================================\n");
printf("// PDB matching\n");
printf("//-----------------------------------------------------------------------------\n");

PIMAGE_DEBUG_DIRECTORY pDebugSection = (PIMAGE_DEBUG_DIRECTORY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
PIMAGE_DEBUG_DIRECTORY pDebugDir = pDebugSection;

DWORD ExpectedSignature = 0;
GUID ExpectedGUID = GUID_NULL;
DWORD ExpectedAge = 0;
BYTE* ExpectedPdbFileName = NULL;

if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == NULL)
printf("%s does not have Debug directory\n\n", file_name);
else
{
    size_t DebugSectionSize = pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    size_t NumbOfDebugDirs = DebugSectionSize / sizeof(IMAGE_DEBUG_DIRECTORY);
    printf("Debug section: size = %zu, NumbOfDebugDirs = %zu %s\n\n", DebugSectionSize, NumbOfDebugDirs,
        (sizeof(IMAGE_DEBUG_DIRECTORY) * NumbOfDebugDirs == DebugSectionSize) ? "" : "BAD");
    if (sizeof(IMAGE_DEBUG_DIRECTORY) * NumbOfDebugDirs != DebugSectionSize)
        return 0;

    for (int i = 0; i < NumbOfDebugDirs; i++)
    {
        if (pDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            printf("IMAGE_DEBUG_TYPE_CODEVIEW DebugDir has been found.\n\n");
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
        // printf ("sizeof (CV_INFO_PDB20) = %d, sizeof(CV_INFO_PDB70) = %d\n", sizeof(CV_INFO_PDB20), sizeof(CV_INFO_PDB70));
        // printf("SizeOfData: %d\n", pDebugDir->SizeOfData);

        ULONG_PTR CvInfo = pDebugDir->AddressOfRawData + (ULONG_PTR)pImageBase;

        if ((((PCV_INFO_PDB20)CvInfo)->CvHeader.CvSignature & 0xFF) == 'N') // NB10
        {
            ExpectedSignature = ((PCV_INFO_PDB20)CvInfo)->Signature;
            ExpectedAge = ((PCV_INFO_PDB20)CvInfo)->Age;
            ExpectedPdbFileName = ((PCV_INFO_PDB20)CvInfo)->PdbFileName;

            printf("CV_INFO_PDB20: ExpectedSignature: %u\n", ExpectedSignature);
            printf("               ExpectedAge: %u\n", ExpectedAge);
            printf("               ExpectedPdbFileName: %s\n", ExpectedPdbFileName);
        }
        else if ((((PCV_INFO_PDB70)CvInfo)->CvSignature & 0xFF) == 'R') // RSDS
        {
            ExpectedGUID = ((PCV_INFO_PDB70)CvInfo)->Signature;
            ExpectedAge = ((PCV_INFO_PDB70)CvInfo)->Age;
            ExpectedPdbFileName = ((PCV_INFO_PDB70)CvInfo)->PdbFileName;

            printf("CV_INFO_PDB70: ExpectedGUIDSignature: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n", ExpectedGUID.Data1, ExpectedGUID.Data2, ExpectedGUID.Data3,
                ExpectedGUID.Data4[0], ExpectedGUID.Data4[1], ExpectedGUID.Data4[2], ExpectedGUID.Data4[3], ExpectedGUID.Data4[4], ExpectedGUID.Data4[5], ExpectedGUID.Data4[6], ExpectedGUID.Data4[7]);

            printf("               ExpectedAge: %u\n", ExpectedAge);
            printf("               ExpectedPdbFileName: %s\n", ExpectedPdbFileName);
        }
        else
            printf("Unknown size of CV_INFO_PDBXX\n");
    }
}
//-----------------------------------------------------------------------------
// match and extract data from .pdb
//-----------------------------------------------------------------------------
printf("\n");
const wchar_t *g_szFilename = NULL;
IDiaDataSource *g_pDiaDataSource = NULL;
IDiaSession *g_pDiaSession = NULL;
IDiaSymbol *g_pGlobalSymbol = NULL;

// typedef std::unordered_map<int, std::string> Name_addr_map_t;
Name_addr_map_t FuncAddrNameMap;
bool is_pdb_matches = 0;
std::wstring RuntimeFuncName;

// if no 'pdb_name' was passed throught 'argv', try to use 'ExpectedPdbFileName'
if ((pdb_name == NULL) && (ExpectedPdbFileName == NULL))
{
    printf("No .pdb file was specified and no 'ExpectedPdbFile' available\n");
}
else if ((pdb_name == NULL) && (ExpectedPdbFileName != NULL))
{
    printf("No .pdb file was specified, but let's try 'ExpectedPdbFile': %s...\n\n", ExpectedPdbFileName);
    pdb_name = (char*)ExpectedPdbFileName;
    is_pdb_provided = 1;
}

if (is_pdb_provided == 1)
{
    //-----------------------------------------------------------------------------
    // convert 'pdb_name' from 'char*' to 'wchar_t*'
    size_t newsize = strlen(pdb_name) + 1;

    // The following creates a buffer large enough to contain   
    // the exact number of characters in the original string  
    // in the new format. If you want to add more characters  
    // to the end of the string, increase the value of newsize  
    // to increase the size of the buffer.  
    wchar_t * w_pdb_name = new wchar_t[newsize];

    // Convert char* string to a wchar_t* string.  
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, w_pdb_name, newsize, pdb_name, _TRUNCATE);
    //-----------------------------------------------------------------------------

    g_szFilename = w_pdb_name;

    if (LoadAndValidateDataFromPdb(g_szFilename, &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol, &ExpectedGUID, ExpectedSignature, ExpectedAge))
    {
        printf(".pdb matches exe/dll.\n");

        if (DumpAllPublicsToMap(g_pGlobalSymbol, &FuncAddrNameMap))
            {
            is_pdb_matches = 1;
            printf ("number of mapped funcs: %zd\n\n", FuncAddrNameMap.size());
            }

        // _print(FuncAddrNameMap);
    }
}
//=============================================================================
// .pdata and .xdata
//-----------------------------------------------------------------------------
printf("\n");
printf("//=============================================================================\n");
printf("// .pdata and .xdata\n");
printf("//-----------------------------------------------------------------------------\n");

PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY pPdataSection = (PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pImageBase + pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY pRuntimeFuncEntry = pPdataSection;

if (pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == NULL)
    printf("%s does not have .pdata section\n\n", file_name);
else
    {
    // printf("%s has .pdata section\n", file_name);

    size_t PdataSectionSize = pPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    size_t NumbOfRuntimeFuncStructs = PdataSectionSize / sizeof (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    //printf("sizeof (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY) = %zu, mult = %zu\n", sizeof (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY), sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY) * NumbOfRuntimeFuncStructs);
    printf(".pdata section: size = %zu, NumbOfRuntimeFuncStructs = %zu %s\n\n", PdataSectionSize, NumbOfRuntimeFuncStructs,
                            (sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY) * NumbOfRuntimeFuncStructs == PdataSectionSize) ? "" : "BAD");
    if (sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY) * NumbOfRuntimeFuncStructs != PdataSectionSize)
        return 0;
    
    printf ("pImageBase = %p\n\n", (ULONG_PTR)pImageBase);
    for (size_t i = 0; i < NumbOfRuntimeFuncStructs; i++)
        {
        printf ("#%zd RUNTIME_FUNCTION: ", i + 1);

        Name_addr_map_t::const_iterator got = FuncAddrNameMap.find((ULONG_PTR)(pRuntimeFuncEntry->BeginAddress));
        if (got != FuncAddrNameMap.end())
            std::wcout << got->second << std::endl;
        else
            std::wcout << std::endl;

        printf (" BeginAddress = %p,\n",      (ULONG_PTR)(pRuntimeFuncEntry->BeginAddress));
        printf (" EndAddress   = %p,\n",      (ULONG_PTR)(pRuntimeFuncEntry->EndAddress));

        if (((pRuntimeFuncEntry->UnwindInfoAddress) & 1) == 0)
            {
            printf(" UnwindInfoAddress = %p\n", (ULONG_PTR)(pRuntimeFuncEntry->UnwindInfoAddress));
            
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
                printf("\t Address of %s handler = %p, ", is_UNW_FLAG_EHANDLER_set ? "exception" : "termination", (ULONG_PTR)(pUNWIND_INFO_Variable->ExceptionHandlerInfo.pExceptionHandler));
                
                Name_addr_map_t::const_iterator got = FuncAddrNameMap.find((ULONG_PTR)(pUNWIND_INFO_Variable->ExceptionHandlerInfo.pExceptionHandler));
                if (got != FuncAddrNameMap.end())
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
            printf(" UnwindData = %p\n", (ULONG_PTR)(pRuntimeFuncEntry->UnwindData));

        printf ("\n");
        pRuntimeFuncEntry++;
        }
    }
//=============================================================================
printf("//=============================================================================\n");

// printf ("\n here %d \n", __LINE__);

// Cleanup();
if (g_pGlobalSymbol) {
    g_pGlobalSymbol->Release();
    g_pGlobalSymbol = NULL;
}

if (g_pDiaSession) {
    g_pDiaSession->Release();
    g_pDiaSession = NULL;
}

CoUninitialize();

UnmapViewOfFile (hFileMapping);
CloseHandle (hFileMapping);
CloseHandle (hFile);

return 0;
}

void print_help(char** argv)
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