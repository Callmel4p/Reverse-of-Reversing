# PE INFECTOR
This is a sample that infect an executable with a shellcode which opens a meessage box and then return to normal execution.

> This is quick, dirty, hard-coded version but at least, it work. I will make some change later to complete it.

Generally, this sample read a PE file into a buffer, create a new section, adjust the PE structure for that new section, copy shellcode to new section, change entry point to new section and write modified PE(the buffer) to a new pe file. Now let me explain each step of infection progess.

## Modifying PE Header
First, we use `fopen, fseek, ftell, fread` to read the PE file to a buffer. Then quickly check whether it's a valid PE file by look at `e_magic` in DOS Header and `Signature` in NT Header. 

## Obtaining necessary data
In PE Header, we need to retrieve:
- `AddressOfEntryPoint`: Original entry point of the program, later used in absolute jump.
- `FileAlignment, SectionAlignment`: Alignment value of the PE File. We can't simply calculate next section position = last section position. The start position must follow the alignment.
- `Number of section, image size`: These value must be change when we adding a new section.

## Fulfilling for new section
We reach to section table by using `IMAGE_FIRST_SECTION`. From here, by align up from last section, we can calculate raw address/size and virtual address/size for our new section.

After that, we copy our shellcode to new section pointer to raw data.

## Constructing the shellcode
I got the shellcode from [this link](https://blackcloud.me/Win32-shellcode-3/). To apply for our purpose, we need to adjust some point:
- Custom the tilte and message: From intend message, we need to reverse it, convert to hex encoding, split into 8 hex characters each block, fullfil with padding and push the hex value into stack where original shellcode push title and message.
- Instead of exit process as the original, we need a absolute jump to original entry point value to jump back original execution path.

Then we follow the guide in the blog to compiling a shellcode block usable in C code.

## Replace the new file
After all of change, the final step is modifing the PE address of entry point to our new section code.

Then write the new buffer to a new file to complete our infection.

## To-do list to complete this sample
- [X] using winAPI to dynamically get PE path.
- [X] replace hard-coded value in number of section and image size to dynamically method.
- [X] overwrite entry point value into shellcode instead of manually place it in nasm and recompile.
- [X] Check section name before create a new section to avoid duplicate.
