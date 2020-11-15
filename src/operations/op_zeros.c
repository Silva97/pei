#include "operations.h"

void op_zeros(pe_t *pe, int section)
{
  pe_block_t block;

  if (section >= 0)
  {
    block = pe_search_biggest_zero_sequence_on_section(pe, section);
    if (block.offset && block.size >= BLOCK_MIN_SIZE)
    {
      PRINT_BLOCK(pe, block);
    }
    return;
  }

  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    block = pe_search_biggest_zero_sequence_on_section(pe, i);
    if (block.offset && block.size >= BLOCK_MIN_SIZE)
    {
      PRINT_BLOCK(pe, block);
    }
  }
}
