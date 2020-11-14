#include "pereader.h"

int pe_search_address_section(pe_t *pe, uint32_t address)
{
  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    pe_section_header_t *section = pe->section_header[i];

    if (address >= section->virtual_address &&
        address <= section->virtual_address + section->virtual_size)
    {
      return i;
    }
  }

  return -1;
}

int pe_search_entrypoint_section(pe_t *pe)
{
  if (pe->type == PE_MAGIC_32BIT)
  {
    pe32_optional_header_t *optional_header = pe->optional_header;
    return pe_search_address_section(pe, optional_header->entry_point);
  }

  pe64_optional_header_t *optional_header = pe->optional_header;
  return pe_search_address_section(pe, optional_header->entry_point);
}
