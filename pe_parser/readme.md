This is a C program to parse a PE file. It will show out some interesting information about a PE file:
- e_magic & e_lfanew in DOS header.
- signature
- machine
- number of section
- magic value
- address of entry point
- image base
- file & section alignment
- checksum
- RVA and size of Import & Export directory

Then it show information of each section, including:
- name
- virtual size & address
- size of raw data & pointer to raw data (raw address)
- Characteristics

Then listing all import & export function of that PE file.

Here is more specific how I do each steps:

# Parse basic information
## Get the file mapping
First of all, we need a couple of function like
```
CreateFile --> CreapFileMapping --> MapViewOfFile
```

After it, we will get a `LPVOID lpBaseAddress` which point to the start of the PE being parsed.
## Parse DOS Header
We know that DOS header location at the start of the PE file. To easier parse it, we create a new pointer 

```
PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)lpBaseAddress
```

From WipAPI struct `IMAGE_DOS_HEADER` we can easily access `e_magic, e_lfanew` and any other information of DOS header.
## Parse NT Header
From `e_lfanew` value, we can reach to NT Header by 
```
PIMAGE_NT_HEADERS nt_header = (PBYTE)lpBaseAddress + e_lfanew
```
Again, we can parse any information in NT Header by take advance of `IMAGE_NT_HEADER` structure.
## Parse File Header
We can get address of File Header from the `nt_header->FileHeader` and then use built-in structure `PIMAGE_FILE_HEADER`. Like
```
PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader
```
## Parse Optional Header
In this header, there is a little different between PE32 and PE64. So we need to check the PE is 32-bit or 64-bit by checking the value `nt_header->OptionalHeader.magic`:
- `0x10B == IMAGE_NT_OPTIONAL_HDR32_MAGIC`
- `0x20B == IMAGE_NT_OPTIONAL_HDR64_MAGIC`.

Then for each type, we have appropiate structure:
- For 32-bit: `PIMAGE_OPTIONAL_HEADERS32`.
- For 64-bit: have a new NT header with type `PIMAGE_NT_HEADERS64` and respectively `PIMAGE_OPTIONAL_HEADERS64`.

Here I use a new nt_header only in if branch to parsing optional header. For the rest of program, I use `PIMAGE_NT_HEADERS32` as default because both PE32 and PE64 have the same NT Header structure.

### Parse Import & Export Directory
In Optional Header, we have `DataDirectory` which is an array of 16 Data Directory Entry (Import, Export, TLS,...). From this, we can get Import Directory by access `DataDirectory[1]` and Export by `DataDirectory[0]`.

# Parse each section
We know that Section Table is start exactly after Optional header. So we can get the pointer to Section table by
```
nt_header
 + sizeof(signature) 
 + sizeof(IMAGE_FILE_HEADER)
 + nt_header->FileHeader.SizeOfOptionalHeader
```
Or easily using `IMAGE_FIRST_SECTION(nt_header)` marco.

From the start of Section Table, every section of a file appear as an array, each element have size is `40 (0x28) bytes` contain metadata for that section.

For each section, we can use structure `PIMAGE_SECTION_HEADERS` to parse information. For number of section, we can extract it from `nt_header->FileHeader->NumberOfSections`.

# Parse import function
In `Import Data Directory` from `DataDirectory[1]`, we can get RVA of the import table. From this value, we need to convert it to raw address and plus with `lpBaseAddress` to reach the raw address of the import table.

From here, every DLL imported appear as an array with each element have type is `PIMAGE_IMPORT_DESCRIPTOR`. We can use a `while` loop to iterate through every DLL until `importDescriptor->Name == 0`.

In structure `PIMAGE_IMPORT_DESCRIPTOR`, there is an important field that we need to list all functions the PE import from the DLL - `OriginalFirstThunk`. It's a RVA of the data we need (listing all function the PE file think it need at first, this could be different than what actually resolved when a PE file is loaded) - a `PIMAGE_THUNK_DATA32/64`, and there is a different between PE32 and PE32+ so we need to determine by `nt_header->OptionalHeader.Magic` as we did in parsing Optional Header. We need to check by bitwise operation 
```
thunkData->u1.Ordinal & 0x80000000 (or 0x8000000000000000)
```
to determine a function is imported by ordinal or by name. Underneath the hood, this is checking whether the highest bit of the `thunkData->u1.Ordinal` is set or not.
- If it's set, return 1, meaning this function is imported by ordinal and the ordinal value is `thunkData->u1.Ordinal` itself (only lower bit contain meaning so we need to cast it to `WORD`).
- Otherwise, return 0, meaning this function is imported by name. `thunkData->u1.AddressOfData` now is RVA of a `PIMAGE_IMPORT_BY_NAME` pointer which contain `Name` field - the function name.

And we can loop through every imported function by 
```
while(thunkData->AddressOfData != 0)
{
    // parse it
    thunkData++;
}
```

# Parse export function
We can reach the start of export directory by the same method used in import. At the start, cast it type to `PIMAGE_EXPORT_DIRECTORY` and parse information:
- `NumberOfFunctions`, `NumberOfNames`.
- `AddressOfFunctions`: RVA of location of exported function.
- `AddressOfNames`: RVA of location where store names of exported function.
- `AddressOfNameOrdinals`: RVA of location where store ordinal of exported function.

There could be functions only exported by ordinal, so it's will be wrong if we just print out `name[i], ordinal[i]` in a loop. We need to loop through every ordinal value, check whether that oridinal value equal to index of the current function we are checking from name listing.
- If yes, it means that the exported function both name and ordinal.
- Otherwise, it means the function only export with ordinal value, no name used.

> _Not every PE file have ordinal value start from 0, it depend on `export->Base` value. The external ordinal is base + internal ordinal._

> _An PE could export a function from other DLL. Therefore, the address of exported function could not belong to the executable itself._
# RVA to file offset
- Step 1: Reach to section table
- Step 2: Loop through every section VA range (start -> start + size).
- Step 3: File offset (raw address) = RVA - section VA + section pointer to raw data.
