#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "pereader.h"
#include "choice.h"

#define PALIGN "%-32s"

#define PRINT_FIELD_N(structure, mask, field_name) \
  printf(                                          \
      PALIGN "%0*" mask,                           \
      #field_name,                                 \
      (int)sizeof structure->field_name * 2,       \
      structure->field_name)

#define PRINT_FIELD(structure, mask, field_name) \
  PRINT_FIELD_N(structure, mask "\n", field_name)

#define PRINT_ALIGNED_N(text, mask, ...) \
  printf(PALIGN mask, text, __VA_ARGS__)

#define PRINT_ALIGNED(text, mask, ...) \
  PRINT_ALIGNED_N(text, mask "\n", __VA_ARGS__)

#define PRINT_FLAG(value, flag, show_separator) \
  {                                             \
    if (value & flag)                           \
    {                                           \
      if (show_separator)                       \
      {                                         \
        putchar('|');                           \
      }                                         \
      fputs(#flag, stdout);                     \
      show_separator = true;                    \
    }                                           \
  }

#define PRINT_DATA_DIRECTORY(optional_header, directory)    \
  PRINT_ALIGNED(#directory,                                 \
                "{ virtual_address: %08x, size: %08x }",    \
                optional_header->directory.virtual_address, \
                optional_header->directory.size)

void pe_dump(pe_t *pe, uint32_t offset, uint32_t size)
{
  pe_seek(pe, offset);

  for (int i = 0; i < size; i++)
  {
    unsigned int c = fgetc(pe->file);

    if (i % 16 == 0)
    {
      if (i)
      {
        putchar('\n');
      }
      printf("%08x  ", offset + i);
    }
    else if (i % 8 == 0)
    {
      fputs("  ", stdout);
    }

    printf("%02x ", c);
  }

  putchar('\n');
}

void pe_show_type(pe_t *pe)
{
  switch (pe->type)
  {
  case MAGIC_32BIT:
    PRINT_ALIGNED("type", "%s", "PE32");
    break;
  case MAGIC_64BIT:
    PRINT_ALIGNED("type", "%s", "PE32+");
    break;
  case MAGIC_ROM:
    PRINT_ALIGNED("type", "%s", "ROM");
    break;
  default:
    PRINT_ALIGNED("type", "%s", "*unknown*");
    break;
  }
}

void pe_show_info(pe_t *pe)
{
  pe_show_type(pe);
  pe_show_coff_machine(pe, true);
  pe_show_subsystem(pe, true);

  fseek(pe->file, 0, SEEK_END);
  size_t size = ftell(pe->file);
  PRINT_ALIGNED("size", "%lu KiB", size / 1024);
}

void pe_show_subsystem(pe_t *pe, bool verbose)
{
  uint16_t subsystem;
  if (pe->type == MAGIC_32BIT)
  {
    pe32_optional_header_t *optional_header = pe->optional_header;
    subsystem = optional_header->subsystem;
  }
  else
  {
    pe64_optional_header_t *optional_header = pe->optional_header;
    subsystem = optional_header->subsystem;
  }

  PRINT_ALIGNED_N("subsystem", "%04" PRIx16, subsystem);
  if (!verbose)
  {
    putchar('\n');
    return;
  }

  char *text = choose(subsystem,
                      CHOICE(SUBSYSTEM_UNKNOWN),
                      CHOICE(NATIVE),
                      CHOICE(WINDOWS_GUI),
                      CHOICE(WINDOWS_CUI),
                      CHOICE(OS2_CUI),
                      CHOICE(POSIX_CUI),
                      CHOICE(NATIVE_WINDOWS),
                      CHOICE(WINDOWS_CE_GUI),
                      CHOICE(EFI_APPLICATION),
                      CHOICE(EFI_BOOT_SERVICE_DRIVER),
                      CHOICE(EFI_RUNTIME_DRIVER),
                      CHOICE(EFI_ROM),
                      CHOICE(XBOX),
                      FINAL(WINDOWS_BOOT_APPLICATION));
  printf(" (%s)\n", text);
}

void pe_show_coff_machine(pe_t *pe, bool verbose)
{
  if (!verbose)
  {
    PRINT_FIELD(pe->coff_header, PRIx16, machine);
    return;
  }

  uint16_t machine = pe->coff_header->machine;
  char *text = choose(machine,
                      CHOICE(MACHINE_UNKNOWN),
                      CHOICE(AM33),
                      CHOICE(AMD64),
                      CHOICE(ARM),
                      CHOICE(ARM64),
                      CHOICE(ARMNT),
                      CHOICE(EBC),
                      CHOICE(I386),
                      CHOICE(IA64),
                      CHOICE(M32R),
                      CHOICE(MIPS16),
                      CHOICE(MIPSFPU),
                      CHOICE(MIPSFPU16),
                      CHOICE(POWERPC),
                      CHOICE(POWERPCFP),
                      CHOICE(R4000),
                      CHOICE(RISCV32),
                      CHOICE(RISCV64),
                      CHOICE(RISCV128),
                      CHOICE(SH3),
                      CHOICE(SH3DSP),
                      CHOICE(SH4),
                      CHOICE(SH5),
                      CHOICE(THUMB),
                      FINAL(WCEMIPSV2));

  PRINT_ALIGNED("machine", "%" PRIx16 " (%s)",
                machine,
                text);
}

void pe_show_coff_characteristics(pe_t *pe, bool verbose)
{
  if (!verbose)
  {
    PRINT_FIELD(pe->coff_header, "x", characteristics);
    return;
  }

  PRINT_FIELD_N(pe->coff_header, "x", characteristics);
  bool separator = false;
  fputs(" (", stdout);
  PRINT_FLAG(pe->coff_header->characteristics, RELOCS_STRIPPED, separator);
  PRINT_FLAG(pe->coff_header->characteristics, EXECUTABLE_IMAGE, separator);
  PRINT_FLAG(pe->coff_header->characteristics, LINE_NUMS_STRIPPED, separator);
  PRINT_FLAG(pe->coff_header->characteristics, LOCAL_SYMS_STRIPPED, separator);
  PRINT_FLAG(pe->coff_header->characteristics, AGGRESSIVE_WS_TRIM, separator);
  PRINT_FLAG(pe->coff_header->characteristics, LARGE_ADDRESS_AWARE, separator);
  PRINT_FLAG(pe->coff_header->characteristics, BYTES_REVERSED_LO, separator);
  PRINT_FLAG(pe->coff_header->characteristics, BIT32_MACHINE, separator);
  PRINT_FLAG(pe->coff_header->characteristics, DEBUG_STRIPPED, separator);
  PRINT_FLAG(pe->coff_header->characteristics, REMOVABLE_RUN_FROM_SWAP, separator);
  PRINT_FLAG(pe->coff_header->characteristics, NET_RUN_FROM_SWAP, separator);
  PRINT_FLAG(pe->coff_header->characteristics, SYSTEM, separator);
  PRINT_FLAG(pe->coff_header->characteristics, UP_SYSTEM_ONLY, separator);
  PRINT_FLAG(pe->coff_header->characteristics, BYTES_REVERSED_HI, separator);
  fputs(")\n", stdout);
}

void pe_show_coff(pe_t *pe, bool verbose)
{
  pe_show_coff_machine(pe, verbose);
  PRINT_FIELD(pe->coff_header, "x", number_of_sections);
  PRINT_FIELD(pe->coff_header, "x", time_date_stamp);
  PRINT_FIELD(pe->coff_header, "x", pointer_to_symbol_table);
  PRINT_FIELD(pe->coff_header, "x", number_of_symbols);
  PRINT_FIELD(pe->coff_header, "x", size_of_optional_header);
  pe_show_coff_characteristics(pe, verbose);
}

void pe_show_dll_characteristics(pe_t *pe, bool verbose)
{
  uint16_t dll_characteristics;
  if (pe->type == MAGIC_32BIT)
  {
    pe32_optional_header_t *optional_header = pe->optional_header;
    dll_characteristics = optional_header->dll_characteristics;
  }
  else
  {
    pe64_optional_header_t *optional_header = pe->optional_header;
    dll_characteristics = optional_header->dll_characteristics;
  }

  if (!verbose)
  {
    PRINT_ALIGNED("dll_characteristics", "%04" PRIx16, dll_characteristics);
    return;
  }

  PRINT_ALIGNED_N("dll_characteristics", "%04" PRIx16, dll_characteristics);
  bool separator = false;
  fputs(" (", stdout);
  PRINT_FLAG(dll_characteristics, HIGH_ENTROPY_VA, separator);
  PRINT_FLAG(dll_characteristics, DYNAMIC_BASE, separator);
  PRINT_FLAG(dll_characteristics, FORCE_INTEGRITY, separator);
  PRINT_FLAG(dll_characteristics, NX_COMPAT, separator);
  PRINT_FLAG(dll_characteristics, NO_ISOLATION, separator);
  PRINT_FLAG(dll_characteristics, NO_SEH, separator);
  PRINT_FLAG(dll_characteristics, NO_BIND, separator);
  PRINT_FLAG(dll_characteristics, APPCONTAINER, separator);
  PRINT_FLAG(dll_characteristics, WDM_DRIVER, separator);
  PRINT_FLAG(dll_characteristics, GUARD_CF, separator);
  PRINT_FLAG(dll_characteristics, TERMINAL_SERVER_AWARE, separator);
  puts(")");
}

void pe32_show_optional_header(pe32_t *pe, bool verbose)
{
  PRINT_FIELD(pe->optional_header, "x", magic);
  PRINT_FIELD(pe->optional_header, "x", major_linker_version);
  PRINT_FIELD(pe->optional_header, "x", minor_linker_version);
  PRINT_FIELD(pe->optional_header, "x", size_of_code);
  PRINT_FIELD(pe->optional_header, "x", size_of_initialized_data);
  PRINT_FIELD(pe->optional_header, "x", size_of_unitialized_data);
  PRINT_FIELD(pe->optional_header, "x", entry_point);
  PRINT_FIELD(pe->optional_header, "x", base_of_code);

  PRINT_FIELD(pe->optional_header, "x", base_of_data);

  PRINT_FIELD(pe->optional_header, PRIx32, image_base);
  PRINT_FIELD(pe->optional_header, PRIx32, section_alignment);
  PRINT_FIELD(pe->optional_header, PRIx32, file_alignment);
  PRINT_FIELD(pe->optional_header, PRIx16, major_os_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_os_version);
  PRINT_FIELD(pe->optional_header, PRIx16, major_image_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_image_version);
  PRINT_FIELD(pe->optional_header, PRIx16, major_subsystem_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_subsystem_version);
  PRINT_FIELD(pe->optional_header, PRIx32, win32_version_value);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_image);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_headers);
  PRINT_FIELD(pe->optional_header, PRIx32, checksum);
  pe_show_subsystem((pe_t *)pe, verbose);
  pe_show_dll_characteristics((pe_t *)pe, verbose);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_stack_reserve);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_stack_commit);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_head_reserve);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_head_commit);
  PRINT_FIELD(pe->optional_header, PRIx32, loader_flags);
  PRINT_FIELD(pe->optional_header, PRIx32, number_of_rva_and_sizes);
}

void pe64_show_optional_header(pe64_t *pe, bool verbose)
{
  PRINT_FIELD(pe->optional_header, "x", magic);
  PRINT_FIELD(pe->optional_header, "x", major_linker_version);
  PRINT_FIELD(pe->optional_header, "x", minor_linker_version);
  PRINT_FIELD(pe->optional_header, "x", size_of_code);
  PRINT_FIELD(pe->optional_header, "x", size_of_initialized_data);
  PRINT_FIELD(pe->optional_header, "x", size_of_unitialized_data);
  PRINT_FIELD(pe->optional_header, "x", entry_point);
  PRINT_FIELD(pe->optional_header, "x", base_of_code);

  PRINT_FIELD(pe->optional_header, PRIx64, image_base);
  PRINT_FIELD(pe->optional_header, PRIx32, section_alignment);
  PRINT_FIELD(pe->optional_header, PRIx32, file_alignment);
  PRINT_FIELD(pe->optional_header, PRIx16, major_os_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_os_version);
  PRINT_FIELD(pe->optional_header, PRIx16, major_image_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_image_version);
  PRINT_FIELD(pe->optional_header, PRIx16, major_subsystem_version);
  PRINT_FIELD(pe->optional_header, PRIx16, minor_subsystem_version);
  PRINT_FIELD(pe->optional_header, PRIx32, win32_version_value);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_image);
  PRINT_FIELD(pe->optional_header, PRIx32, size_of_headers);
  PRINT_FIELD(pe->optional_header, PRIx32, checksum);
  pe_show_subsystem((pe_t *)pe, verbose);
  pe_show_dll_characteristics((pe_t *)pe, verbose);
  PRINT_FIELD(pe->optional_header, PRIx64, size_of_stack_reserve);
  PRINT_FIELD(pe->optional_header, PRIx64, size_of_stack_commit);
  PRINT_FIELD(pe->optional_header, PRIx64, size_of_head_reserve);
  PRINT_FIELD(pe->optional_header, PRIx64, size_of_head_commit);
  PRINT_FIELD(pe->optional_header, PRIx32, loader_flags);
  PRINT_FIELD(pe->optional_header, PRIx32, number_of_rva_and_sizes);
}

void pe_show_optional_header(pe_t *pe, bool verbose)
{
  if (pe->type == MAGIC_32BIT)
  {
    pe32_show_optional_header((pe32_t *)pe, verbose);
  }
  else
  {
    pe64_show_optional_header((pe64_t *)pe, verbose);
  }
}

void pe32_show_data_directories(pe32_t *pe)
{
  PRINT_DATA_DIRECTORY(pe->optional_header, export_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, import_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, resource_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, exception_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, certificate_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, base_relocation_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, debug);
  PRINT_DATA_DIRECTORY(pe->optional_header, architecture);
  PRINT_DATA_DIRECTORY(pe->optional_header, global_ptr);
  PRINT_DATA_DIRECTORY(pe->optional_header, tls_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, load_config_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, bound_import);
  PRINT_DATA_DIRECTORY(pe->optional_header, iat);
  PRINT_DATA_DIRECTORY(pe->optional_header, delay_import_descriptor);
  PRINT_DATA_DIRECTORY(pe->optional_header, clr_runtime_header);
}

void pe64_show_data_directories(pe64_t *pe)
{
  PRINT_DATA_DIRECTORY(pe->optional_header, export_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, import_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, resource_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, exception_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, certificate_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, base_relocation_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, debug);
  PRINT_DATA_DIRECTORY(pe->optional_header, architecture);
  PRINT_DATA_DIRECTORY(pe->optional_header, global_ptr);
  PRINT_DATA_DIRECTORY(pe->optional_header, tls_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, load_config_table);
  PRINT_DATA_DIRECTORY(pe->optional_header, bound_import);
  PRINT_DATA_DIRECTORY(pe->optional_header, iat);
  PRINT_DATA_DIRECTORY(pe->optional_header, delay_import_descriptor);
  PRINT_DATA_DIRECTORY(pe->optional_header, clr_runtime_header);
}

void pe_show_data_directories(pe_t *pe)
{
  if (pe->type == MAGIC_32BIT)
  {
    pe32_show_data_directories((pe32_t *)pe);
  }
  else
  {
    pe64_show_data_directories((pe64_t *)pe);
  }
}

void pe_show_section_characteristics(pe_t *pe, unsigned int section_number, bool verbose)
{
  if (!verbose)
  {
    PRINT_FIELD(pe->section_header[section_number], PRIx32, characteristics);
    return;
  }

  PRINT_FIELD_N(pe->section_header[section_number], PRIx32, characteristics);

  uint32_t characteristics = pe->section_header[section_number]->characteristics;
  bool separator = false;
  fputs(" (", stdout);
  PRINT_FLAG(characteristics, TYPE_NO_PAD, separator);
  PRINT_FLAG(characteristics, CNT_CODE, separator);
  PRINT_FLAG(characteristics, CNT_INITIALIZED_DATA, separator);
  PRINT_FLAG(characteristics, CNT_UNINITIALIZED_DATA, separator);
  PRINT_FLAG(characteristics, LNK_OTHER, separator);
  PRINT_FLAG(characteristics, LNK_INFO, separator);
  PRINT_FLAG(characteristics, LNK_REMOVE, separator);
  PRINT_FLAG(characteristics, LNK_COMDAT, separator);
  PRINT_FLAG(characteristics, GPREL, separator);
  PRINT_FLAG(characteristics, MEM_PURGEABLE, separator);
  PRINT_FLAG(characteristics, MEM_16BIT, separator);
  PRINT_FLAG(characteristics, MEM_LOCKED, separator);
  PRINT_FLAG(characteristics, MEM_PRELOAD, separator);
  PRINT_FLAG(characteristics, ALIGN_1BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_2BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_4BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_8BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_16BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_32BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_64BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_128BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_256BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_512BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_1024BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_2048BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_4096BYTES, separator);
  PRINT_FLAG(characteristics, ALIGN_8192BYTES, separator);
  PRINT_FLAG(characteristics, LNK_NRELOC_OVFL, separator);
  PRINT_FLAG(characteristics, MEM_DISCARDABLE, separator);
  PRINT_FLAG(characteristics, MEM_NOT_CACHED, separator);
  PRINT_FLAG(characteristics, MEM_NOT_PAGED, separator);
  PRINT_FLAG(characteristics, MEM_SHARED, separator);
  PRINT_FLAG(characteristics, MEM_EXECUTE, separator);
  PRINT_FLAG(characteristics, MEM_READ, separator);
  PRINT_FLAG(characteristics, MEM_WRITE, separator);
  fputs(")\n", stdout);
}

void pe_show_section_header(pe_t *pe, unsigned int section_number, bool verbose)
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
  pe_show_section_characteristics(pe, section_number, verbose);
}

void pe_show_all_section_headers(pe_t *pe, bool verbose)
{
  for (int i = 0; i < pe->coff_header->number_of_sections; i++)
  {
    printf("\n--- Section #%d ---\n", i);
    pe_show_section_header(pe, i, verbose);
  }
}
