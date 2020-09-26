#include <string.h>
#include "pereader.h"

#define PALIGN "%-32s"

#define PRINT_FIELD(structure, field_name)   \
  printf(                                    \
      PALIGN "%0*x\n",                       \
      #field_name,                           \
      (int)sizeof structure->field_name * 2, \
      structure->field_name)

#define PRINT_ALIGNED(text, mask, ...) \
  printf(PALIGN mask "\n", text, __VA_ARGS__)

void pe_show_type(pe_t *pe)
{
  switch (pe->type)
  {
  case PE_MAGIC_32BIT:
    PRINT_ALIGNED("type", "%s", "32-bit");
    break;
  case PE_MAGIC_64BIT:
    PRINT_ALIGNED("type", "%s", "64-bit");
    break;
  case PE_MAGIC_ROM:
    PRINT_ALIGNED("type", "%s", "ROM");
    break;
  default:
    PRINT_ALIGNED("type", "%s", "*unknown*");
    break;
  }
}

void pe_show_coff(pe_t *pe)
{
  PRINT_FIELD(pe->coff_header, machine);
  PRINT_FIELD(pe->coff_header, number_of_sections);
  PRINT_FIELD(pe->coff_header, time_date_stamp);
  PRINT_FIELD(pe->coff_header, pointer_to_symbol_table);
  PRINT_FIELD(pe->coff_header, number_of_symbols);
  PRINT_FIELD(pe->coff_header, size_of_optional_header);
  PRINT_FIELD(pe->coff_header, characteristics);
}

void pe32_show_optional_header(pe_t *pe)
{
  pe32_optional_header_t *optional_header = pe->optional_header;

  PRINT_FIELD(optional_header, magic);
  PRINT_FIELD(optional_header, major_linker_version);
  PRINT_FIELD(optional_header, minor_linker_version);
  PRINT_FIELD(optional_header, size_of_code);
  PRINT_FIELD(optional_header, size_of_initialized_data);
  PRINT_FIELD(optional_header, size_of_unitialized_data);
  PRINT_FIELD(optional_header, entry_point);
  PRINT_FIELD(optional_header, base_of_code);
}

void pe64_show_optional_header(pe_t *pe)
{
  pe64_optional_header_t *optional_header = pe->optional_header;

  PRINT_FIELD(optional_header, magic);
  PRINT_FIELD(optional_header, major_linker_version);
  PRINT_FIELD(optional_header, minor_linker_version);
  PRINT_FIELD(optional_header, size_of_code);
  PRINT_FIELD(optional_header, size_of_initialized_data);
  PRINT_FIELD(optional_header, size_of_unitialized_data);
  PRINT_FIELD(optional_header, entry_point);
  PRINT_FIELD(optional_header, base_of_code);
}
