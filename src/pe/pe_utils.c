#include <stdbool.h>
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
  if (pe->type == MAGIC_32BIT)
  {
    pe32_optional_header_t *optional_header = pe->optional_header;
    return pe_search_address_section(pe, optional_header->entry_point);
  }

  pe64_optional_header_t *optional_header = pe->optional_header;
  return pe_search_address_section(pe, optional_header->entry_point);
}

pe_block_t pe_search_biggest_zero_sequence_on_section(pe_t *pe, unsigned int section)
{
  pe_block_t biggest = {
      .offset = 0,
      .size = 0,
      .section = section,
  };
  uint64_t current_offset = 0;
  size_t current_size = 0;
  bool in_sequence = false;

  uint32_t start_offset = pe->section_header[section]->pointer_to_raw_data;
  pe_seek(pe, start_offset);

  uint64_t i;
  for (i = 0; i < pe->section_header[section]->size_of_raw_data; i++)
  {
    if (fgetc(pe->file) == '\0')
    {
      if (!in_sequence)
      {
        current_offset = start_offset + i;
        current_size = 1;
        in_sequence = true;
      }
      else
      {
        current_size++;
      }
    }
    else if (in_sequence)
    {
      in_sequence = false;
      if (current_size > biggest.size)
      {
        biggest.offset = current_offset;
        biggest.size = current_size;
      }
    }
  }

  return biggest;
}

pe_block_t pe_search_biggest_zero_sequence(pe_t *pe)
{
  pe_block_t block;
  pe_block_t biggest = {
      .offset = 0,
      .size = 0,
      .section = 0,
  };

  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    block = pe_search_biggest_zero_sequence_on_section(pe, i);
    if (block.size > biggest.size)
    {
      biggest = block;
    }
  }

  return biggest;
}
