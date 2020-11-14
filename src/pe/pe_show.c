#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "pereader.h"

#define PALIGN "%-32s"

#define PRINT_FIELD_N(structure, mask, field_name) \
  printf(                                          \
      PALIGN "%0*" mask,                           \
      #field_name,                                 \
      (int)sizeof structure->field_name * 2,       \
      structure->field_name)

#define PRINT_FIELD(structure, mask, field_name) \
  PRINT_FIELD_N(structure, mask "\n", field_name)

#define PRINT_ALIGNED(text, mask, ...) \
  printf(PALIGN mask "\n", text, __VA_ARGS__)

#define PRINT_FLAG(value, flag, show_separator) \
  {                                             \
    if (value & flag)                           \
    {                                           \
      if (show_separator)                       \
      {                                         \
        putchar('|');                           \
      }                                         \
      fputs(#flag, stdout);                     \
    }                                           \
  }

void pe_show_type(pe_t *pe)
{
  switch (pe->type)
  {
  case MAGIC_32BIT:
    PRINT_ALIGNED("type", "%s", "32-bit");
    break;
  case MAGIC_64BIT:
    PRINT_ALIGNED("type", "%s", "64-bit");
    break;
  case MAGIC_ROM:
    PRINT_ALIGNED("type", "%s", "ROM");
    break;
  default:
    PRINT_ALIGNED("type", "%s", "*unknown*");
    break;
  }
}

void pe_show_coff_characteristics(pe_t *pe, bool verbose)
{
  if (!verbose)
  {
    PRINT_FIELD(pe->coff_header, "x", characteristics);
    return;
  }

  PRINT_FIELD_N(pe->coff_header, "x", characteristics);
  fputs(" (", stdout);
  PRINT_FLAG(pe->coff_header->characteristics, RELOCS_STRIPPED, false);
  PRINT_FLAG(pe->coff_header->characteristics, EXECUTABLE_IMAGE, true);
  PRINT_FLAG(pe->coff_header->characteristics, LINE_NUMS_STRIPPED, true);
  PRINT_FLAG(pe->coff_header->characteristics, LOCAL_SYMS_STRIPPED, true);
  PRINT_FLAG(pe->coff_header->characteristics, AGGRESSIVE_WS_TRIM, true);
  PRINT_FLAG(pe->coff_header->characteristics, LARGE_ADDRESS_AWARE, true);
  PRINT_FLAG(pe->coff_header->characteristics, BYTES_REVERSED_LO, true);
  PRINT_FLAG(pe->coff_header->characteristics, BIT32_MACHINE, true);
  PRINT_FLAG(pe->coff_header->characteristics, DEBUG_STRIPPED, true);
  PRINT_FLAG(pe->coff_header->characteristics, REMOVABLE_RUN_FROM_SWAP, true);
  PRINT_FLAG(pe->coff_header->characteristics, NET_RUN_FROM_SWAP, true);
  PRINT_FLAG(pe->coff_header->characteristics, SYSTEM, true);
  PRINT_FLAG(pe->coff_header->characteristics, UP_SYSTEM_ONLY, true);
  PRINT_FLAG(pe->coff_header->characteristics, BYTES_REVERSED_HI, true);
  fputs(")\n", stdout);
}

void pe_show_coff(pe_t *pe, bool verbose)
{
  PRINT_FIELD(pe->coff_header, "x", number_of_sections);
  PRINT_FIELD(pe->coff_header, "x", time_date_stamp);
  PRINT_FIELD(pe->coff_header, "x", pointer_to_symbol_table);
  PRINT_FIELD(pe->coff_header, "x", number_of_symbols);
  PRINT_FIELD(pe->coff_header, "x", size_of_optional_header);
  pe_show_coff_characteristics(pe, verbose);
}

void pe32_show_optional_header(pe_t *pe)
{
  pe32_optional_header_t *optional_header = pe->optional_header;

  PRINT_FIELD(optional_header, "x", magic);
  PRINT_FIELD(optional_header, "x", major_linker_version);
  PRINT_FIELD(optional_header, "x", minor_linker_version);
  PRINT_FIELD(optional_header, "x", size_of_code);
  PRINT_FIELD(optional_header, "x", size_of_initialized_data);
  PRINT_FIELD(optional_header, "x", size_of_unitialized_data);
  PRINT_FIELD(optional_header, "x", entry_point);
  PRINT_FIELD(optional_header, "x", base_of_code);

  PRINT_FIELD(optional_header, PRIx32, image_base);
  PRINT_FIELD(optional_header, PRIx32, section_alignment);
  PRINT_FIELD(optional_header, PRIx32, file_alignment);
  PRINT_FIELD(optional_header, PRIx16, major_os_version);
  PRINT_FIELD(optional_header, PRIx16, minor_os_version);
  PRINT_FIELD(optional_header, PRIx16, major_image_version);
  PRINT_FIELD(optional_header, PRIx16, minor_image_version);
  PRINT_FIELD(optional_header, PRIx16, major_subsystem_version);
  PRINT_FIELD(optional_header, PRIx16, minor_subsystem_version);
  PRINT_FIELD(optional_header, PRIx32, win32_version_value);
  PRINT_FIELD(optional_header, PRIx32, size_of_image);
  PRINT_FIELD(optional_header, PRIx32, size_of_headers);
  PRINT_FIELD(optional_header, PRIx32, checksum);
  PRINT_FIELD(optional_header, PRIx16, subsystem);
  PRINT_FIELD(optional_header, PRIx16, dll_characteristics);
  PRINT_FIELD(optional_header, PRIx32, size_of_stack_reserve);
  PRINT_FIELD(optional_header, PRIx32, size_of_stack_commit);
  PRINT_FIELD(optional_header, PRIx32, size_of_head_reserve);
  PRINT_FIELD(optional_header, PRIx32, size_of_head_commit);
  PRINT_FIELD(optional_header, PRIx32, loader_flags);
  PRINT_FIELD(optional_header, PRIx32, number_of_rva_and_sizes);
}

void pe64_show_optional_header(pe_t *pe)
{
  pe64_optional_header_t *optional_header = pe->optional_header;

  PRINT_FIELD(optional_header, "x", magic);
  PRINT_FIELD(optional_header, "x", major_linker_version);
  PRINT_FIELD(optional_header, "x", minor_linker_version);
  PRINT_FIELD(optional_header, "x", size_of_code);
  PRINT_FIELD(optional_header, "x", size_of_initialized_data);
  PRINT_FIELD(optional_header, "x", size_of_unitialized_data);
  PRINT_FIELD(optional_header, "x", entry_point);
  PRINT_FIELD(optional_header, "x", base_of_code);

  PRINT_FIELD(optional_header, PRIx64, image_base);
  PRINT_FIELD(optional_header, PRIx32, section_alignment);
  PRINT_FIELD(optional_header, PRIx32, file_alignment);
  PRINT_FIELD(optional_header, PRIx16, major_os_version);
  PRINT_FIELD(optional_header, PRIx16, minor_os_version);
  PRINT_FIELD(optional_header, PRIx16, major_image_version);
  PRINT_FIELD(optional_header, PRIx16, minor_image_version);
  PRINT_FIELD(optional_header, PRIx16, major_subsystem_version);
  PRINT_FIELD(optional_header, PRIx16, minor_subsystem_version);
  PRINT_FIELD(optional_header, PRIx32, win32_version_value);
  PRINT_FIELD(optional_header, PRIx32, size_of_image);
  PRINT_FIELD(optional_header, PRIx32, size_of_headers);
  PRINT_FIELD(optional_header, PRIx32, checksum);
  PRINT_FIELD(optional_header, PRIx16, subsystem);
  PRINT_FIELD(optional_header, PRIx16, dll_characteristics);
  PRINT_FIELD(optional_header, PRIx64, size_of_stack_reserve);
  PRINT_FIELD(optional_header, PRIx64, size_of_stack_commit);
  PRINT_FIELD(optional_header, PRIx64, size_of_head_reserve);
  PRINT_FIELD(optional_header, PRIx64, size_of_head_commit);
  PRINT_FIELD(optional_header, PRIx32, loader_flags);
  PRINT_FIELD(optional_header, PRIx32, number_of_rva_and_sizes);
}

void pe_show_section_header(pe_t *pe, unsigned int section_number)
{
  PRINT_ALIGNED("name", "%-8s", pe->section_header[section_number]->name);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, virtual_size);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, virtual_address);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, size_of_raw_data);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, pointer_to_raw_data);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, pointer_to_relocations);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, pointer_to_line_numbers);
  PRINT_FIELD(pe->section_header[section_number], PRIx16, number_of_relocations);
  PRINT_FIELD(pe->section_header[section_number], PRIx16, number_of_line_numbers);
  PRINT_FIELD(pe->section_header[section_number], PRIx32, characteristics);
}

void pe_show_all_section_headers(pe_t *pe)
{
  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    printf("\n--- Section #%d ---\n", i);
    pe_show_section_header(pe, i);
  }
}
