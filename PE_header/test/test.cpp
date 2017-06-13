// test.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"


template <typename M> void _print(const M& m);


int main (int argc, char* argv[])
{
int ret_val = 0, ret_code = 0;

//=============================================================================
// Parse command line input
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
            // if '-o' is present, redirect output to given file
            if ((err = freopen_s(&stream, argv[i + 1], "w", stdout)) != 0)
                fprintf(stdout, "error on freopen, error = %d\n", GetLastError ());
            }
        }

if (argc > 1)
    for (int i = 1; i < argc; i++)
        {
        if ((argv[i][0] == '-') && (argv[i][1] == '?')) // '-p' : print help
            {
            print_help (argv);
            return 0;
            }

        if ((argv[i][0] == '-') && (argv[i][1] == 'f')) // '-f' : path to file
            {
            argv_idx_of_file = i + 1;
            continue;
            }

        if ((argv[i][0] == '-') && (argv[i][1] == 'p')) // '-p' : path to pdb
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

//=============================================================================
// Create file mapping
//-----------------------------------------------------------------------------
PVOID pImageBase = NULL;

if ((ret_code = MapExecutableFile (file_name, &pImageBase)) != 0)
    {
    printf ("MapExecutableFile: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//=============================================================================
// DOS and PE header
//-----------------------------------------------------------------------------
printf ("//=============================================================================\n");
printf ("// PE header\n");
printf ("//-----------------------------------------------------------------------------\n");

if ((ret_code = DumpDosAndPeMagics (pImageBase)) != 0)
    {
    printf ("DumpDosAndPeMagics: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }

PIMAGE_NT_HEADERS pPeHeader = GET_P_PE_HEADER (pImageBase);

Supported_machines_t arch_of_executable = MACHINE_UNKNOWN;
if ((arch_of_executable = GetBitnessOfExecutable (pPeHeader)) == MACHINE_UNKNOWN)
    {
    printf ("Can't parse files for this machine architecture\n");
    return EXIT_FAILURE;
    }

int is_x64 = (arch_of_executable == MACHINE_AMD64) ? 1 : 0;

printf ("\n");
printf ("Bitness of executable: %s-bit\n", (is_x64) ? "64" : "32");

#ifndef _AMD64_ // this is x86 build
if (is_x64)
    {
    printf ("\n");
    printf ("Sorry, 32-bit program can't parse 64-bit executables safely.\n");
    printf ("\n");
    printf ("//=============================================================================\n");
    exit (EXIT_FAILURE);
    }
#endif

printf ("\n");
if ((ret_code = DumpListOfSections (pPeHeader)) != 0)
    {
    printf ("DumpListOfSections: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//=============================================================================
// Import table
//-----------------------------------------------------------------------------
printf ("\n");
printf ("\n");
printf ("//=============================================================================\n");
printf ("// Import table\n");
printf ("//-----------------------------------------------------------------------------\n");

if (is_x64)
    ret_code = DumpImportTable <PIMAGE_NT_HEADERS64, PIMAGE_THUNK_DATA64, ULONGLONG> (pImageBase, (PIMAGE_NT_HEADERS64)pPeHeader, IMAGE_ORDINAL_FLAG64);
else
    ret_code = DumpImportTable <PIMAGE_NT_HEADERS32, PIMAGE_THUNK_DATA32, DWORD> (pImageBase, (PIMAGE_NT_HEADERS32)pPeHeader, IMAGE_ORDINAL_FLAG32);

if (ret_code == ERROR_NO_MORE_ITEMS)
    printf ("%s does not have Import table\n", file_name);
else if (ret_code != 0)
    {
    printf ("DumpImportTable: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//=============================================================================
// Export table
//-----------------------------------------------------------------------------
printf ("\n");
printf ("//=============================================================================\n");
printf ("// Export table\n");
printf ("//-----------------------------------------------------------------------------\n");

if (is_x64)
    ret_code = DumpExportTable <PIMAGE_NT_HEADERS64> (pImageBase, (PIMAGE_NT_HEADERS64)pPeHeader);
else
    ret_code = DumpExportTable <PIMAGE_NT_HEADERS32> (pImageBase, (PIMAGE_NT_HEADERS32)pPeHeader);

if (ret_code == ERROR_NO_MORE_ITEMS)
    printf ("%s does not have Export table\n", file_name);
else if (ret_code != 0)
    {
    printf ("DumpExportTable: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }

if (is_x64) // this is x64 executable => .pdata/.xdata sections => .pdb matching
{
//=============================================================================
// PDB matching
//-----------------------------------------------------------------------------
// extract expected GUIDs from exe/dll
//-----------------------------------------------------------------------------
printf("\n");
printf("\n");
printf("//=============================================================================\n");
printf("// PDB matching\n");
printf("//-----------------------------------------------------------------------------\n");

DWORD ExpectedSignature = 0;
GUID ExpectedGUID = GUID_NULL;
DWORD ExpectedAge = 0;
BYTE* ExpectedPdbFileName = NULL;

ret_code = DumpAndGetExpected_GUID_Age_PdbFileName (
        pImageBase,
        pPeHeader,
        
        &ExpectedSignature,
        &ExpectedGUID,
        &ExpectedAge,
        &ExpectedPdbFileName);

if (ret_code == ERROR_NO_MORE_ITEMS)
    printf ("%s does not have Debug table\n", file_name);
else if (ret_code != 0)
    {
    printf ("DumpExportTable: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//-----------------------------------------------------------------------------
// match and extract data from .pdb
//-----------------------------------------------------------------------------
printf("\n");
const wchar_t *g_szFilename = NULL;
IDiaDataSource *g_pDiaDataSource = NULL;
IDiaSession *g_pDiaSession = NULL;
IDiaSymbol *g_pGlobalSymbol = NULL;

Name_addr_map_t FuncAddrNameMap;
bool is_pdb_matches = 0;
std::wstring RuntimeFuncName;

// if no 'pdb_name' was passed throught 'argv', try to use 'ExpectedPdbFileName'
if ((pdb_name == NULL) && (ExpectedPdbFileName == NULL))
    printf("No .pdb file was specified and no 'ExpectedPdbFile' is available\n");
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
    wchar_t* w_pdb_name = new wchar_t[newsize];

    // Convert char* string to a wchar_t* string.  
    size_t convertedChars = 0;
    if (mbstowcs_s (&convertedChars, w_pdb_name, newsize, pdb_name, _TRUNCATE) != 0)
        {
        perror ("mbstowcs_s: failed to convert 'pdb_name' to wchars");
        return EXIT_FAILURE;
        }
    //-----------------------------------------------------------------------------

    g_szFilename = w_pdb_name;

    if (LoadAndValidateDataFromPdbFile (g_szFilename, &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol, &ExpectedGUID, ExpectedSignature, ExpectedAge))
        {
        printf(".pdb matches exe/dll.\n");
        
        size_t tmp_size = 0;

        if (DumpAllPublicsToMap (g_pGlobalSymbol, &FuncAddrNameMap))
            {
            is_pdb_matches = 1;
            printf ("number of mapped public funcs: %zd\n", tmp_size = FuncAddrNameMap.size());
            }

        if (DumpAllGlobalsToMap (g_pGlobalSymbol, &FuncAddrNameMap))
            {
            is_pdb_matches = 1;
            printf ("number of mapped global funcs: %zd\n", FuncAddrNameMap.size() - tmp_size);
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

ret_code = DumpPdataXdata (pImageBase, pPeHeader, &FuncAddrNameMap);

if (ret_code == ERROR_NO_MORE_ITEMS)
    printf ("%s does not have .pdata section\n", file_name);
else if (ret_code != 0)
    {
    printf ("DumpPdataXdata: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//-----------------------------------------------------------------------------
// Cleanup after .pdb parsing (only for x64)
//-----------------------------------------------------------------------------
if (CleanupSymbols (&g_pGlobalSymbol, &g_pDiaSession) != 0)
    {
    printf ("Cleanup: failed with ret_code = %d, with error = %d\n", ret_code, GetLastError ());
    return EXIT_FAILURE;
    }
//=============================================================================
} // end of if-then
else // for x86
{
printf ("\n");
printf ("\n");
printf ("//=============================================================================\n");
printf ("\n");
printf ("32-bit executables don't have .pdata and .xdata sections, so no pdb matching was done\n");
}

printf ("\n");
printf ("//=============================================================================\n");

UnmapViewOfFile (pImageBase);

return 0;
}


template <typename M> void _print(const M& m)
    {
    std::cout << m.size() << " elements: ";

    for (const auto& p : m)
        {
        //wprintf (L"(%x, %s)", p.first, p.second);
        std::wcout << "(" << p.first << ", " << p.second << ") ";
        }

    std::cout << std::endl;
    }
