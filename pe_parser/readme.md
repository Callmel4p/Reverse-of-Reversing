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
