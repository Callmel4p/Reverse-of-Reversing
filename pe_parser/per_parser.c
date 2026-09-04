#include <windows.h>
#include <stdio.h>

DWORD rvaToFileOffset(PIMAGE_NT_HEADERS32 nt_header, DWORD RVA)
{// Formular: File offset = RVA - section VA + Pointer to Raw Data
    WORD numberOfSection = nt_header->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionTable = IMAGE_FIRST_SECTION(nt_header);

    for (WORD i = 0; i < numberOfSection; i++)
    {
        PIMAGE_SECTION_HEADER section = &sectionTable[i];
        if (RVA >= section->VirtualAddress && RVA < section->VirtualAddress + section->SizeOfRawData)
        {
            return RVA - section->VirtualAddress + section->PointerToRawData;
        }
    }
    return 0;

}

void list_import_function(PIMAGE_DATA_DIRECTORY import_dir, PIMAGE_NT_HEADERS32 nt_header, LPVOID lpBaseAddress)
{
    DWORD importRVA = import_dir->VirtualAddress;
    DWORD importRawAddr = rvaToFileOffset(nt_header, importRVA);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)lpBaseAddress + importRawAddr);

    while(importDesc->Name != 0)
    {
        char* DLL_name = (char*)((PBYTE)lpBaseAddress + rvaToFileOffset(nt_header,importDesc->Name));
        printf("Import from DLL: %s\n", DLL_name);
        DWORD thunkRawAddr = rvaToFileOffset(nt_header,importDesc->OriginalFirstThunk);
        if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_THUNK_DATA32 thunkData = (PIMAGE_THUNK_DATA32)((PBYTE)lpBaseAddress + thunkRawAddr);
            while(thunkData->u1.AddressOfData != 0)
            {
                if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                {
                    printf("\tImported by ordinal:\t#%x\n", (WORD)thunkData->u1.Ordinal);
                }
                else
                {
                    DWORD nameRawAddr = rvaToFileOffset(nt_header,thunkData->u1.AddressOfData);
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)lpBaseAddress + nameRawAddr);
                    char* func_name = importByName->Name;
                    printf("\tImported by name:\t%s\n",func_name);
                }
                thunkData ++;
            }
        }
        else
        {
            PIMAGE_THUNK_DATA64 thunkData = (PIMAGE_THUNK_DATA64)((PBYTE)lpBaseAddress + thunkRawAddr);
            while(thunkData->u1.AddressOfData != 0)
            {
                if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    printf("\tImported by ordinal:\t#%x\n", (WORD)thunkData->u1.Ordinal);
                }
                else
                {
                    DWORD nameRawAddr = rvaToFileOffset(nt_header,thunkData->u1.AddressOfData);
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)lpBaseAddress + nameRawAddr);
                    char* func_name = importByName->Name;
                    printf("\tImported by name:\t%s\n",func_name);
                }
                thunkData ++;
            }
        }
        printf("\n");
        importDesc ++;
    }
}

void list_export_function(PIMAGE_DATA_DIRECTORY export_dir, PIMAGE_NT_HEADERS32 nt_header, LPVOID lpBaseAddress)
{
    DWORD exportRVA = export_dir->VirtualAddress;
    DWORD exportRawAddr = rvaToFileOffset(nt_header, exportRVA);

    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)lpBaseAddress + exportRawAddr);

    if (exportTable->AddressOfFunctions == 0)
    {
        printf("\nThere is no export function !!\n");
        return;
    }
    printf("Number of export functions: %#x\n",exportTable->NumberOfFunctions);
    printf("Number of function exported by name: %#x\n", exportTable->NumberOfNames);

    DWORD* func = (DWORD*)((PBYTE)lpBaseAddress + rvaToFileOffset(nt_header,exportTable->AddressOfFunctions));
    DWORD* names = (DWORD*)((PBYTE)lpBaseAddress + rvaToFileOffset(nt_header,exportTable->AddressOfNames));
    WORD* ordinals = (WORD*)((PBYTE)lpBaseAddress + rvaToFileOffset(nt_header,exportTable->AddressOfNameOrdinals));

    for (DWORD i = 0; i < exportTable->NumberOfFunctions; i++)
    {
        WORD ordinal = exportTable->Base + i;

        char* name = nullptr;
        for (DWORD j = 0; j < exportTable->NumberOfNames; j++)
        {
            if (ordinals[j] == i)
            {
                name = (char *)((PBYTE)lpBaseAddress + rvaToFileOffset(nt_header,names[j]));
                break;
            }
        }
        if (!name) 
        {
            printf("\tExport function %-50s with oridinal is %#x\n","<noname>",ordinal);
        }
        else
        {
            printf("\tExport function %-50s with oridinal is %#x\n",name,ordinal);
        }
    }
}

void parse_section(WORD numberOfSections, PIMAGE_SECTION_HEADER sectionTable) // sectionTable == start address of section table
{                                                                             // get by IMAGE_FIRST_SECTION(ntheader)
    for (WORD i = 0; i < numberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER section = &sectionTable[i];
        //(char *)section + i * sizeof(IMAGE_SECTION_HEADER) (each section header structure is 40 bytes)

        printf("Section %u\n", i);
        printf("\tName:\t\t\t%.8s\n", section->Name);
        printf("\tVirtualSize:\t\t%#x\n", section->Misc.VirtualSize);
        printf("\tVirtualAddress:\t\t%#x\n", section->VirtualAddress);
        printf("\tSizeOfRawData:\t\t%#x\n", section->SizeOfRawData);
        printf("\tPointerToRawData:\t%#x\n", section->PointerToRawData);
        printf("\tCharacteristics:\t%#x\n", section->Characteristics);
    }
}

void parse_basic_information(LPCSTR lpFileName)
{
    HANDLE hFile = CreateFileA(lpFileName,0xC0000000,1,0,4,0x80,0);
    DWORD dwMaximumSizeLow = GetFileSize(hFile,0);
    HANDLE hFileMappingObject = CreateFileMappingA(hFile, 0, 4, 0, dwMaximumSizeLow, 0);


    PIMAGE_DATA_DIRECTORY import_dir;
    PIMAGE_DATA_DIRECTORY export_dir;


    LPVOID lpBaseAddress = MapViewOfFile(hFileMappingObject, 6, 0, 0, dwMaximumSizeLow);

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)lpBaseAddress;
    printf("DOS HEADER:\n");
    printf("\te_magic:\t\t%#hx\n" , dos_header->e_magic); 
    printf("\te_lfanew:\t\t%#hx\n" , dos_header->e_lfanew);
    printf("\n");


    PIMAGE_NT_HEADERS32 nt_header = (PIMAGE_NT_HEADERS32)((PBYTE)lpBaseAddress + dos_header->e_lfanew);
    printf("NT HEADER:\n");
    printf("\tsignature:\t\t%#x\n" , nt_header->Signature);
    printf("\n");


    PIMAGE_FILE_HEADER file_header = &(nt_header->FileHeader);
    printf("FILE HEADER:\n");
    printf("\tmachine:\t\t%#hx\n" , file_header->Machine);
    printf("\tnumber of section:\t%#hx\n" , file_header->NumberOfSections);
    printf("\n");
    
    if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_OPTIONAL_HEADER32 opt_header = &(nt_header->OptionalHeader);
        printf("OPTIONAL HEADER:\n");
        printf("\tmagic value:\t\t%#hx\n", nt_header->OptionalHeader.Magic);
        printf("\taddress of entry point:\t%#x\n" , opt_header->AddressOfEntryPoint);
        printf("\tImageBase:\t\t%#x\n" , opt_header->ImageBase);
        printf("\tFile alignment:\t\t%#x\n" , opt_header->FileAlignment);
        printf("\tSection alignment:\t%#x\n" , opt_header->SectionAlignment);
        printf("\tSize of image:\t\t%#x\n" , opt_header->SizeOfImage);
        printf("\tChecksum:\t\t%#x\n", opt_header->CheckSum);

        import_dir = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // 1
        printf("\tImport Data Directory:\n");
        printf("\t\tRVA:\t\t%#x\n", import_dir->VirtualAddress);
        printf("\t\tSize:\t\t%#x\n", import_dir->Size);

        export_dir = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; // 0
        printf("\tExport Data Directory:\n");
        printf("\t\tRVA:\t\t%#x\n", export_dir->VirtualAddress);
        printf("\t\tSize:\t\t%#x\n", export_dir->Size);
    }
    else
    {
        PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)((PBYTE)lpBaseAddress + dos_header->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 opt_header = (PIMAGE_OPTIONAL_HEADER64)&(nt_header->OptionalHeader);
        printf("OPTIONAL HEADER:\n");
        printf("\taddress of entry point:\t%#x\n" , opt_header->AddressOfEntryPoint);
        printf("\tImageBase:\t\t%#llx\n" , opt_header->ImageBase);
        printf("\tFile alignment:\t\t%#x\n" , opt_header->FileAlignment);
        printf("\tSection alignment:\t%#x\n" , opt_header->SectionAlignment);
        printf("\tSize of image:\t\t%#x\n" , opt_header->SizeOfImage);
        printf("\tChecksum:\t\t%#x\n", opt_header->CheckSum);

        import_dir = &opt_header->DataDirectory[1];
        printf("\tImport Data Directory:\n");
        printf("\t\tRVA:\t\t%#x\n", import_dir->VirtualAddress);
        printf("\t\tSize:\t\t%#x\n", import_dir->Size);

        export_dir = &opt_header->DataDirectory[0];
        printf("\tExport Data Directory:\n");
        printf("\t\tRVA:\t\t%#x\n", export_dir->VirtualAddress);
        printf("\t\tSize:\t\t%#x\n", export_dir->Size);
    }

    // parse each section
    int NumberOfSection = nt_header->FileHeader.NumberOfSections;

    PIMAGE_SECTION_HEADER sectionTable = IMAGE_FIRST_SECTION(nt_header);
    WORD numberOfSections = nt_header->FileHeader.NumberOfSections;
    parse_section(NumberOfSection, sectionTable);

    // list import function
    list_import_function(import_dir,nt_header, lpBaseAddress);
    
    // list export function
    list_export_function(export_dir, nt_header, lpBaseAddress);
}

int main()
{
    int result = 0;
    LPCSTR lpFileName;
    printf("Path to PE file: ");
    scanf("%s", lpFileName);
    parse_basic_information(lpFileName);

}