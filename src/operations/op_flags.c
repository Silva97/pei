#include "operations.h"

void op_flags(pe_t *pe, char *flags, int section)
{
  if (section >= 0)
  {
    pe_section_header_t *header = pe->section_header[section];
    SET_FLAG(header->characteristics, MEM_READ, strchr(flags, 'r'));
    SET_FLAG(header->characteristics, MEM_WRITE, strchr(flags, 'w'));
    SET_FLAG(header->characteristics, MEM_EXECUTE, strchr(flags, 'x'));
    goto end;
  }

  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    pe_section_header_t *header = pe->section_header[i];
    SET_FLAG(header->characteristics, MEM_READ, strchr(flags, 'r'));
    SET_FLAG(header->characteristics, MEM_WRITE, strchr(flags, 'w'));
    SET_FLAG(header->characteristics, MEM_EXECUTE, strchr(flags, 'x'));
  }

end:
  pe_write_header(pe);
  return;
}
