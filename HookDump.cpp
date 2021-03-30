/**************************************************************************
*
*                                    _ _
*                                   (_) |
*  _______ _ __ ___  _ __   ___ _ __ _| |
* |_  / _ \ '__/ _ \| '_ \ / _ \ '__| | |
*  / /  __/ | | (_) | |_) |  __/ |  | | |
* /___\___|_|  \___/| .__/ \___|_|  |_|_|
*                   | |
*                   |_|
*
*
* Hook dumper
*
* (c) ZEROPERIL LTD 2021
*
*  Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
*  See LICENSE file for more information
*
**************************************************************************/

#include <windows.h>
#include <winternl.h>
#include <assert.h>
#include <string>
#include <map>
#include <vector>
#include <memory>

#include <stdio.h>
#include <inttypes.h>

#include "zydis/Zydis.h"

#pragma comment(lib, "ntdll")

extern "C"
{
    ULONG __declspec(dllimport) NTAPI NtQueryInformationFile(
      HANDLE                 FileHandle,
      PVOID                  IoStatusBlock,
      PVOID                  FileInformation,
      ULONG                  Length,
      FILE_INFORMATION_CLASS FileInformationClass
    );
}


#include "LibraryList.inl"

namespace zp
{
    CONST DWORD FUNCTION_BYTES = 32;
    CONST DWORD INSTRUCTION_COUNT = 3;

    //--------------------------------------------------------------------------------

    struct ExportedFunctionData
    {
        std::string   Name;
        UINT_PTR      ProcAddress;
        UINT_PTR      ResolvedProcAddress;
        BYTE          FirstBytes[FUNCTION_BYTES];
        UINT_PTR      ModuleBase;
    };

    //--------------------------------------------------------------------------------

    typedef std::map< UINT_PTR, std::shared_ptr< ExportedFunctionData > >  ExportDataMap;
    typedef std::pair< UINT_PTR, std::shared_ptr< ExportedFunctionData > > ExportDataPair;

    //--------------------------------------------------------------------------------

    template< typename T >
    __inline BOOL IS_ORDINAL(T pvTest)
    {
        CONST UINT_PTR MASK = ~(UINT_PTR(0xFFFF));
        return ((UINT_PTR)pvTest & MASK) == 0 ? TRUE : FALSE;
    }


    //--------------------------------------------------------------------------------

    PIMAGE_SECTION_HEADER ResolveVAToSection
    (
        UINT_PTR pImageBase,
        IMAGE_NT_HEADERS* pNTHeaders,
        UINT_PTR va
    )
    {
        PIMAGE_SECTION_HEADER pFirst = IMAGE_FIRST_SECTION(pNTHeaders);

        if (pFirst)
        {
            for (DWORD dwCurrent = 0; dwCurrent < pNTHeaders->FileHeader.NumberOfSections; ++dwCurrent)
            {
                PIMAGE_SECTION_HEADER pCurrent = &pFirst[dwCurrent];

                if (va >= (UINT_PTR)pCurrent->VirtualAddress &&
                    va < ((UINT_PTR)pCurrent->VirtualAddress + (UINT_PTR)pCurrent->Misc.VirtualSize))
                {
                    return pCurrent;
                }
            }
        }

        return NULL;
    }

    //--------------------------------------------------------------------------------

    UINT_PTR ResolveVA(UINT_PTR ImageBase, IMAGE_NT_HEADERS* pNTHeaders, UINT_PTR VA, BOOLEAN bFlatFile = FALSE)
    {
        if (bFlatFile)
        {
            //FLAT FILE
            PIMAGE_SECTION_HEADER pSection = ResolveVAToSection(ImageBase, pNTHeaders, VA);

            if (pSection)
            {
                VA = VA - pSection->VirtualAddress;

                //in a file we need to use the RVA
                return ((UINT_PTR)pSection->PointerToRawData + (UINT_PTR)ImageBase + VA);
            }
        }
        else
        {
            return ((UINT_PTR)VA + (UINT_PTR)ImageBase);
        }

        return NULL;
    }

    //--------------------------------------------------------------------------------

    template < typename T_Type >
    T_Type GetImageDirectory
    (
        UINT_PTR pImageBase,
        IMAGE_NT_HEADERS* pNTHeaders,
        DWORD Entry,
        BOOLEAN bFlatFile = FALSE,
        OPTIONAL OUT CONST IMAGE_DATA_DIRECTORY** ppOutDir = NULL)
    {

        if (pNTHeaders && pImageBase)
        {
            CONST IMAGE_DATA_DIRECTORY* pDir = &(pNTHeaders->OptionalHeader.DataDirectory[Entry]);

            if (ppOutDir)
            {
                *ppOutDir = pDir;
            }

            if (pDir->VirtualAddress && pDir->Size)
            {
                return (T_Type)ResolveVA(pImageBase, pNTHeaders, pDir->VirtualAddress, bFlatFile);
            }
        }

        return NULL;
    }

    //--------------------------------------------------------------------------------

    typedef VOID(*FN_ENUMERATE)(CONST CHAR* szFunctionName, IMAGE_NT_HEADERS* pNtHeaders, LPVOID pContext);

    //--------------------------------------------------------------------------------

    VOID EnumerateExports(UINT_PTR ImageBase, FN_ENUMERATE fpEnum, LPVOID pContext, BOOL bFlatFile)
    {
        if (ImageBase && fpEnum)
        {
            __try
            {
                IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)ImageBase;
                if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(((UINT_PTR)ImageBase) + pDos->e_lfanew);
                    if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
                    {
                        if (pNTHeader->OptionalHeader.NumberOfRvaAndSizes)
                        {
                            CONST IMAGE_EXPORT_DIRECTORY* pExports = GetImageDirectory<CONST IMAGE_EXPORT_DIRECTORY*>((UINT_PTR)ImageBase, pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, bFlatFile);

                            if (pExports)
                            {
                                CONST DWORD INVALID_FUNCTION = DWORD(-1);

                                WORD* pOrdinals = (WORD*)ResolveVA(ImageBase, pNTHeader, pExports->AddressOfNameOrdinals, bFlatFile);
                                PDWORD pNames = (PDWORD)ResolveVA(ImageBase, pNTHeader, pExports->AddressOfNames, bFlatFile);
                                DWORD functionIndex = INVALID_FUNCTION;

                                for (DWORD x = 0; x < pExports->NumberOfNames; ++x)
                                {
                                    fpEnum((CONST CHAR*)ResolveVA(ImageBase, pNTHeader, pNames[x], bFlatFile), pNTHeader, pContext);
                                }
                            }
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                printf("[-] ERROR: GetProcVirtualAddress CRASH 0x%X\n", GetExceptionCode());
            }
        }
        else
        {
            printf("[-] ERROR: EnumerateExports Invalid parameters\n");
        }

    }


    //--------------------------------------------------------------------------------

    UINT_PTR GetProcVirtualAddress(UINT_PTR ImageBase, CONST CHAR* pszProcName, BOOLEAN bFlatFile)
    {
        UINT_PTR pRet = NULL;
        if (ImageBase && pszProcName)
        {
            __try
            {
                IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)ImageBase;
                if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(((UINT_PTR)ImageBase) + pDos->e_lfanew);
                    if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
                    {
                        if (pNTHeader->OptionalHeader.NumberOfRvaAndSizes)
                        {
                            CONST IMAGE_DATA_DIRECTORY* pDataDir = NULL;
                            CONST IMAGE_EXPORT_DIRECTORY* pExports = GetImageDirectory<CONST IMAGE_EXPORT_DIRECTORY*>((UINT_PTR)ImageBase, pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, bFlatFile, &pDataDir);
                           
                            if (pExports)
                            {
                                CONST DWORD INVALID_FUNCTION = DWORD(-1);

                                WORD* pOrdinals = (WORD*)ResolveVA(ImageBase, pNTHeader, pExports->AddressOfNameOrdinals, bFlatFile);
                                PDWORD pNames = (PDWORD)ResolveVA(ImageBase, pNTHeader, pExports->AddressOfNames, bFlatFile);
                                DWORD functionIndex = INVALID_FUNCTION;

                                if (IS_ORDINAL(pszProcName))
                                {
                                    //warning C4311: 'type cast': pointer truncation from 'const CHAR *' to 'DWORD'
#pragma warning(suppress:4311)
                                    DWORD ordinal = ((DWORD)pszProcName) - pExports->Base;

                                    if (ordinal < pExports->NumberOfNames)
                                    {
                                        functionIndex = pOrdinals[ordinal];
                                    }
                                }
                                else
                                {
                                    for (INT64 index = 0; index < pExports->NumberOfNames; ++index)
                                    {
                                        LPCSTR pszNext = (LPCSTR)ResolveVA(ImageBase, pNTHeader, pNames[index], bFlatFile);

                                        if (strcmp(pszNext, pszProcName) == 0)
                                        {
                                            if (index >= 0 && index < pExports->NumberOfNames)
                                            {
                                                functionIndex = pOrdinals[index];
                                            }

                                            break;
                                        }
                                    }
                                }

                                if (functionIndex != INVALID_FUNCTION)
                                {
                                    PDWORD pFuncs = (PDWORD)ResolveVA(ImageBase, pNTHeader, pExports->AddressOfFunctions, bFlatFile);

                                    if (functionIndex < pExports->NumberOfFunctions)
                                    {
                                        pRet = ((UINT_PTR)pFuncs[functionIndex]);
                                     
                                        //check if it's this section, in which case it is forwarded
                                        //so return NULL                                     
                                        if (pRet >= pDataDir->VirtualAddress && pRet < (pDataDir->VirtualAddress + pDataDir->Size) )
                                        {

#if defined(_DEBUG)
                                            CONST CHAR* pRedirect = (CONST CHAR*)ResolveVA(ImageBase, pNTHeader, pRet, bFlatFile);
#endif
                                            pRet = NULL;
                                        }
                                    }
                                }

                            }
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                printf("[-] ERROR: GetProcVirtualAddress CRASH 0x%X\n", GetExceptionCode());
            }
        }
        else
        {
            printf("[-] ERROR: GetProcVirtualAddress invalid parameters");
        }

        return pRet;
    }

    //--------------------------------------------------------------------------------

    struct FunctionListContext
    {
        ExportDataMap& DataMap;
        HMODULE        Module;
        HMODULE        FlatModule;
        BOOL           FlatFile;
    };

    //--------------------------------------------------------------------------------

    VOID FunctionListBuilderCallback(CONST CHAR* szFunctionName, IMAGE_NT_HEADERS* pNtHeaders, LPVOID pContext)
    {
        if (szFunctionName)
        {
            if (FALSE == IS_ORDINAL(szFunctionName))
            {
                if (strlen(szFunctionName))
                {
                    _ASSERT(pContext);
                    FunctionListContext* pCtx = (FunctionListContext*)pContext;
                    std::shared_ptr< ExportedFunctionData > pData = std::make_shared<ExportedFunctionData>();

                    pData->Name = szFunctionName;
                    pData->ResolvedProcAddress = GetProcVirtualAddress((pCtx->FlatFile)?(UINT_PTR)pCtx->FlatModule : (UINT_PTR)pCtx->Module, szFunctionName, pCtx->FlatFile);
                    pData->ModuleBase = (pCtx->FlatFile) ? (UINT_PTR)pCtx->FlatModule : (UINT_PTR)pCtx->Module;
                    
                    //only insert if we could resolve it ourselves
                    //NULL == forwarded function
                    if (pData->ResolvedProcAddress)
                    {
                        if (FALSE == pCtx->FlatFile)
                        {
                            pData->ProcAddress = (UINT_PTR)GetProcAddress(pCtx->Module, szFunctionName);

                            if (pData->ProcAddress)
                            {
                                //adjust offsets
                                pData->ProcAddress -= (UINT_PTR)pCtx->Module;
                            }
                        }

                        //now read function bytes
                        memcpy(pData->FirstBytes, (LPVOID)ResolveVA((pCtx->FlatFile) ? (UINT_PTR)pCtx->FlatModule : (UINT_PTR)pCtx->Module, pNtHeaders, pData->ResolvedProcAddress, pCtx->FlatFile), sizeof(pData->FirstBytes));

                        //add to map
                        pCtx->DataMap.insert(ExportDataPair(pData->ResolvedProcAddress, pData));

                    }
                    //else
                    //{
                    //    printf("    [+] %s [FORWARDED]\n", pData->Name.c_str());
                    //}
                }
            }
        }
    }

    //--------------------------------------------------------------------------------

    HMODULE GetModuleFromAddress(CONST LPVOID pImport, IN BOOL bVerbose)
    {
        _ASSERT(pImport);
        
        CONST BYTE* pbScan = (CONST BYTE*)pImport;
        
        for(;;)
        {
            __try
            {
                CONST IMAGE_DOS_HEADER* pDosHeader = (CONST IMAGE_DOS_HEADER*)pbScan;
                
                if(pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
                {                 
                    if (((ULONG_PTR)pDosHeader & 0xFFF) == 0)
                    {
                        CONST BYTE* pbNtHeader = pbScan + pDosHeader->e_lfanew;

                        if (pDosHeader->e_lfanew >= sizeof(IMAGE_DOS_HEADER) && pDosHeader->e_lfanew < 1024)
                        {
                            CONST IMAGE_NT_HEADERS* pNtHeaders = (CONST IMAGE_NT_HEADERS*)pbNtHeader;

                            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
                            {
                                return (HMODULE)pbScan;
                            }
                        }
                    }
                }
                
                pbScan--;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                if( bVerbose )
                    printf("[-] ERROR: GetModuleFromAddress exception 0x%.8X caught while searching\n", GetExceptionCode() );
                
                return NULL;
            }
        }
        
        return NULL;
    }

    //--------------------------------------------------------------------------------

    VOID BuildExportedFunctionList(CONST ModuleInfo& moduleInfo, IN BOOL bFlatFile, IN BOOL bVerbose, OUT ExportDataMap& outExpFun)
    {
        if (bVerbose)
            printf("[*] Examine: %s\n", moduleInfo.pszName );

        if (bFlatFile)
        {
            HMODULE hModule = LoadLibraryA(moduleInfo.pszName);
            if (hModule)
            {
                std::vector<BYTE> buffer;
                CHAR fileName[MAX_PATH] = { 0 };
                GetModuleFileNameA(hModule, fileName, MAX_PATH);

                HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);


                if (hFile != INVALID_HANDLE_VALUE)
                {
                    DWORD dwRead = 0;
                    DWORD dwSize = GetFileSize(hFile, NULL);
                    buffer.resize(dwSize);

                    if (ReadFile(hFile, buffer.data(), dwSize, &dwRead, NULL) && dwSize == dwRead)
                    {
                        FunctionListContext ctx = { outExpFun, hModule, (HMODULE)buffer.data(), TRUE };
                        EnumerateExports((UINT_PTR)buffer.data(), FunctionListBuilderCallback, &ctx, TRUE);
                    }
                    else
                    {
                        printf("[-] ERROR: failed to read '%s', error 0x%X\n", moduleInfo.pszName, GetLastError());
                    }

                    CloseHandle(hFile);

                }
                else
                {
                    if (bVerbose)
                        printf("[-] ERROR: failed to open '%s', error 0x%X\n", moduleInfo.pszName, GetLastError());
                }
            }
            else
            {
                if (bVerbose)
                    printf("[-] ERROR: failed to load '%s', error 0x%X\n", moduleInfo.pszName, GetLastError());
            }
        }
        else
        {
            HMODULE hModule = NULL;
            
            if( moduleInfo.pStaticImport )
            {
                hModule = GetModuleFromAddress(moduleInfo.pStaticImport, bVerbose);
            }
            else
            {
                hModule = LoadLibraryA(moduleInfo.pszName);
            }

            if (hModule)
            {
                FunctionListContext ctx = { outExpFun, hModule, NULL, FALSE };
                EnumerateExports((UINT_PTR)hModule, FunctionListBuilderCallback, &ctx, FALSE);
            }
            else
            {
                if (bVerbose)
                    printf("[-] ERROR: failed to load '%s', error 0x%X\n", moduleInfo.pszName, GetLastError());
            }
        }
    }

    //--------------------------------------------------------------------------------

    BOOL DisassembleInstructions(_In_ CONST BYTE* pbData, _In_ DWORD cbData, _Inout_ ZydisDecodedInstruction* pInstructions, _In_ DWORD countInstructions, _Out_ DWORD& outCount )
    {
        outCount = 0;

        if (pbData && cbData && pInstructions && countInstructions)
        {
            // Initialize decoder context
            ZydisDecoder decoder;

#if defined(_M_IX86)
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#endif

            ZyanUSize length = cbData;
            INT32 offset = 0;

            for (DWORD x = 0; x < countInstructions && (length > 0); ++x)
            {
                // Loop over the instructions in our buffer.
                BOOL bOK = ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, pbData + offset, length, &pInstructions[x]));

                if (bOK)
                {
                    offset += pInstructions[x].length;
                    length -= pInstructions[x].length;
                    ++outCount;
                }
                else
                {
                    break;
                }
            }
        }

        return outCount > 0 ? TRUE : FALSE;
    }

    //--------------------------------------------------------------------------------

    VOID DumpInstruction(CONST ZydisDecodedInstruction& instruction, UINT_PTR Address )
    {
        // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
        // visualize relative addressing
        ZyanU64 runtime_address = Address;

        // Initialize formatter. Only required when you actually plan to do instruction
        // formatting ("disassembling"), like we do here
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        // Print current instruction pointer.
        printf("    [*] %016" PRIX64 "  ", runtime_address);

        // Format & print the binary instruction structure to human readable format
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
            runtime_address);

        printf("%s\n", buffer);
    }

    //--------------------------------------------------------------------------------

    BOOL CheckWOWStubHook(BOOL bVerbose)
    {
        struct ZP_TEB
        {
            NT_TIB NtTib;

            PVOID EnvironmentPointer;
            CLIENT_ID ClientId;
            PVOID ActiveRpcHandle;
            PVOID ThreadLocalStoragePointer;
            PPEB ProcessEnvironmentBlock;

            ULONG LastErrorValue;
            ULONG CountOfOwnedCriticalSections;
            PVOID CsrClientThread;
            PVOID Win32ThreadInfo;
            ULONG User32Reserved[26];
            ULONG UserReserved[5];
            PVOID WOW32Reserved;
        };

        ZP_TEB* pTeb = (ZP_TEB*)NtCurrentTeb();

        if (pTeb)
        {
            if (pTeb->WOW32Reserved)
            {
                __try
                {

                    ZydisDecodedInstruction instruction;
                    DWORD dwInstructionCount = 0;

                    if (DisassembleInstructions(*((CONST BYTE**)pTeb->WOW32Reserved), 16, &instruction, 16, dwInstructionCount))
                    {
                        //check for inter-segment branch
                        if (instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_FAR)
                        {
                            printf("\n[-] WOW64 system call stub [WOW]\n");
                            DumpInstruction(instruction, (UINT_PTR)pTeb->WOW32Reserved);
                            return TRUE;
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    if (bVerbose)
                        printf("[-] ERROR: CheckWOWStubHook exception trapped 0x%X\n", GetExceptionCode() );
                }
            }
        }

        return FALSE;
    }

}


int main(int argc, char** argv)
{
    using namespace zp;

    DWORD count = 0;
    BOOL bVerbose = FALSE;

    if (argc == 2 && 0 == strcmp(argv[1], "-v"))
        bVerbose = TRUE;

    for (DWORD x = 0; x < _ARRAYSIZE(g_szLibraryList); ++x)
    {
        CONST ModuleInfo& moduleInfo = g_szLibraryList[x];
        
        ExportDataMap dataMapWin;
        ExportDataMap dataMapDisk;

        BuildExportedFunctionList(moduleInfo, FALSE, bVerbose, dataMapWin);
        BuildExportedFunctionList(moduleInfo, TRUE, bVerbose, dataMapDisk);

        for (CONST ExportDataPair& p : dataMapWin)
        {
            if (bVerbose && p.second->ResolvedProcAddress && p.second->ProcAddress)
            {
                if (p.second->ResolvedProcAddress != p.second->ProcAddress)
                {
                    printf("[-] %s!%s [GPA]\n", moduleInfo.pszName, p.second->Name.c_str());
                    printf("    [*] 0x%p -> 0x%p\n", (LPVOID)(p.second->ResolvedProcAddress + p.second->ModuleBase), (LPVOID)(p.second->ProcAddress + p.second->ModuleBase));
                    ++count;
                }
            }

            ExportDataMap::iterator i = dataMapDisk.find(p.first);

            if (i != dataMapDisk.end())
            {
                if (p.second->ResolvedProcAddress && p.second->ResolvedProcAddress != i->second->ResolvedProcAddress)
                {
                    printf("[-] %s!%s [EAT]\n", moduleInfo.pszName, p.second->Name.c_str());
                    printf("    [*] 0x%p -> 0x%p\n", (LPVOID)(p.second->ResolvedProcAddress + p.second->ModuleBase), (LPVOID)(i->second->ResolvedProcAddress + p.second->ModuleBase));
                    ++count;
                }

                if (memcmp(p.second->FirstBytes, i->second->FirstBytes, sizeof(p.second->FirstBytes)) != 0)
                {
                    ZydisDecodedInstruction instruction[INSTRUCTION_COUNT];
                    ZydisDecodedInstruction diskInstruction[INSTRUCTION_COUNT];

                    DWORD dwOffset = 0;
                    DWORD dwInstrCount = 0;
                    DWORD dwDiskInstrCount = 0;

                    if (DisassembleInstructions(p.second->FirstBytes, sizeof(p.second->FirstBytes), &instruction[0], INSTRUCTION_COUNT, dwInstrCount))
                    {
                        if (DisassembleInstructions(i->second->FirstBytes, sizeof(i->second->FirstBytes), &diskInstruction[0], INSTRUCTION_COUNT, dwDiskInstrCount))
                        {
                            for (DWORD y = 0; y < min(dwDiskInstrCount, dwInstrCount); ++y)
                            {
                                if (ZYDIS_BRANCH_TYPE_NEAR == instruction[y].meta.branch_type && ZYDIS_CATEGORY_UNCOND_BR == instruction[y].meta.category)
                                {
                                    if (diskInstruction[y].meta.category != instruction[y].meta.category)
                                    {
                                        printf("[-] %s!%s [JMP]\n", moduleInfo.pszName, p.second->Name.c_str());
                                        DumpInstruction(instruction[y], p.second->ProcAddress + dwOffset + p.second->ModuleBase);
                                        ++count;
                                        break;
                                    }
                                }

                                dwOffset += instruction[y].length;
                            }
                        }
                        else
                        {
                            if(bVerbose)
                                printf("[-] ERROR: %s!%s disassemble 2 failed\n", moduleInfo.pszName, p.second->Name.c_str());
                        }
                    }
                    else
                    {
                        if (bVerbose)
                            printf("[-] ERROR: %s!%s disassemble 1 failed\n", moduleInfo.pszName, p.second->Name.c_str());
                    }
                }
            }
        }
    }

#if defined(_M_IX86)
    if (CheckWOWStubHook(bVerbose))
    {
        ++count;
    }
#endif

    printf("%d hooks found\n", count);




    return 0;
}
