#include "pereader.h"
#include <stdio.h>

void pe_seek(pe_t *pe, long int offset)
{
  fseek(pe->file, offset, SEEK_SET);
}

void pe_write(pe_t *pe, void *data, size_t size)
{
  fwrite(data, size, 1, pe->file);
}

void pe_write_header(pe_t *pe)
{
  int32_t signature_address;
  pe_seek(pe, PE_SIGNATURE_ADDRESS_OFFSET);
  if (!fread(&signature_address, sizeof signature_address, 1, pe->file))
  {
    return;
  }

  pe_seek(pe, signature_address + PE_SIGNATURE_SIZE);
  fwrite(pe->coff_header, sizeof(pe_coff_header_t), 1, pe->file);

  if (pe->type == MAGIC_32BIT)
  {
    fwrite(pe->optional_header, sizeof(pe32_optional_header_t), 1, pe->file);
  }
  else
  {
    fwrite(pe->optional_header, sizeof(pe64_optional_header_t), 1, pe->file);
  }

  for (int i = 0; i < pe->number_of_sections; i++)
  {
    fwrite(pe->section_header[i], sizeof(pe_section_header_t), 1, pe->file);
  }
}
