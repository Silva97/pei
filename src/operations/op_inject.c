#include <stdlib.h>
#include "operations.h"

#define READ_DATA_SIZE 512

void op_inject(pe_t *pe, char *filename, int section)
{
  static char data[READ_DATA_SIZE];
  pe_block_t block;
  size_t size;
  unsigned char code[] = {
      0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, oep
      0xff, 0xe0,                   // jmp eax
  };

  FILE *file = fopen(filename, "rb");
  if (!file)
  {
    fprintf(stderr, "Injection error: File '%s' not found.\n", filename);
    exit(EXIT_FAILURE);
  }

  if (section < 0)
  {
    block = pe_search_biggest_zero_sequence(pe);
  }
  else
  {
    block = pe_search_biggest_zero_sequence_on_section(pe, section);
  }

  fseek(file, 0, SEEK_END);
  int fsize = ftell(file);
  if (fsize + sizeof(code) > block.size)
  {
    fprintf(stderr,
            "The biggest zeroed block on section #%" PRId16 " is not big enough to write the code on it.\n"
            "Code size:  %d + %zu\n"
            "Block size: %" PRId64 "\n",
            block.section,
            fsize,
            sizeof(code),
            block.size);
  }

  fseek(file, 0, SEEK_SET);
  pe_seek(pe, block.offset);
  do
  {
    size = fread(data, 1, READ_DATA_SIZE, file);
    fwrite(data, size, 1, pe->file);
  } while (size == READ_DATA_SIZE);

  int64_t vaddress = pe_offset_to_vaddress(pe, block.offset);
  if (vaddress < 0)
  {
    fputs("Unexpected error on try to inject code.\n", stderr);
    exit(EXIT_FAILURE);
  }

  // Update the entry point and save the Original Entry Point
  // to add a jump to it.
  uint32_t oep = pe_update_entrypoint(pe, vaddress);
  *((uint32_t *)&code[1]) = pe_image_base(pe) + oep;

  // Make section executable
  pe->section_header[block.section]->characteristics |= MEM_EXECUTE;

  fwrite(code, sizeof(code), 1, pe->file);
  pe_write_header(pe);

  printf("Writed code of %d bytes on offset " PRIoff " of section #%" PRId16 " '%s'\n",
         fsize,
         block.offset,
         block.section,
         pe->section_header[block.section]->name);
}
