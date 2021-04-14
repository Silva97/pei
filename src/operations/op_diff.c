#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "operations.h"

#define C_ORIGINAL "\x1b[31m"
#define C_MODIFIED "\x1b[32m"
#define C_NORMAL "\x1b[0m"
#define DUMP_BLOCK_SIZE 16

#define DIFF_FIELD(field, name)                                     \
  if (first_pe->field != second_pe->field)                          \
  {                                                                 \
    print_field(name, first_pe->field, second_pe->field, colorize); \
  }

#define DIFF_DATA_DIRECTORY(datadir)                                                             \
  DIFF_FIELD(optional_header->datadir.virtual_address, "optional." #datadir ".virtual_address"); \
  DIFF_FIELD(optional_header->datadir.size, "optional." #datadir ".size")

#define DIFF_SECTION_FIELD(section, field)                                                                                \
  if (first_pe->section_header[section]->field != second_pe->section_header[section]->field)                              \
  {                                                                                                                       \
    char fullname[48];                                                                                                    \
    sprintf(fullname, "section.%d." #field, section);                                                                     \
    print_field(fullname, first_pe->section_header[section]->field, second_pe->section_header[section]->field, colorize); \
  }

#define graphchar(c) ((isgraph(c) || c == ' ') \
                          ? c                  \
                          : '.')

static void print_field(char *name, uint64_t value1, uint64_t value2, bool colorize);
static void print_string_field(char *name, char *value1, char *value2, bool colorize);
static void print_coff_diff(pe_t *first_pe, pe_t *second_pe, bool colorize);
static void print_optional_diff(pe_t *first_pe, pe_t *second_pe, bool colorize);
static void print_optional32_diff(pe32_t *first_pe, pe32_t *second_pe, bool colorize);
static void print_optional64_diff(pe64_t *first_pe, pe64_t *second_pe, bool colorize);
static void print_section_diff(pe_t *first_pe, pe_t *second_pe, unsigned int section, bool colorize);
static void print_dump_diff(pe_t *first_pe, pe_t *second_pe, unsigned int section, bool colorize);
static void print_data_diff(uint32_t offset, unsigned char *first_data, unsigned char *second_data, size_t size, bool colorize);

void op_diff(pe_t *first_pe, char *filename, bool colorize, int section)
{
  pe_t *second_pe = pe_parse(pe_open(filename));
  if (!second_pe)
  {
    fprintf(stderr, "Diff error: File '%s' not found or isn't a valid PE32/PE32+ executable.\n", filename);
    exit(EXIT_FAILURE);
  }

  print_coff_diff(first_pe, second_pe, colorize);
  print_optional_diff(first_pe, second_pe, colorize);

  for (int i = 0; i < first_pe->number_of_sections; i++)
  {
    print_section_diff(first_pe, second_pe, i, colorize);
  }

  if (section > first_pe->number_of_sections)
  {
    goto end;
  }

  // Show differences between section's datas
  putchar('\n');
  if (section >= 0)
  {
    print_dump_diff(first_pe, second_pe, section, colorize);
    goto end;
  }

  for (int i = 0; i < first_pe->number_of_sections && i < second_pe->number_of_sections; i++)
  {
    print_dump_diff(first_pe, second_pe, i, colorize);
  }

end:
  pe_free(second_pe);
}

static void print_field(char *name, uint64_t value1, uint64_t value2, bool colorize)
{
  const char *mask = colorize
                         ? "%s " C_ORIGINAL "0x%x" C_MODIFIED " 0x%x" C_NORMAL "\n"
                         : "%s 0x%x 0x%x\n";

  printf(mask, name, value1, value2);
}

static void print_string_field(char *name, char *value1, char *value2, bool colorize)
{
  const char *mask = colorize
                         ? "%s " C_ORIGINAL "%s" C_MODIFIED " %s" C_NORMAL "\n"
                         : "%s %s %s\n";

  printf(mask, name, value1, value2);
}

static void print_coff_diff(pe_t *first_pe, pe_t *second_pe, bool colorize)
{
  DIFF_FIELD(coff_header->machine, "coff.machine");
  DIFF_FIELD(coff_header->number_of_sections, "coff.number_of_sections");
  DIFF_FIELD(coff_header->time_date_stamp, "coff.time_date_stamp");
  DIFF_FIELD(coff_header->pointer_to_symbol_table, "coff.pointer_to_symbol_table");
  DIFF_FIELD(coff_header->number_of_symbols, "coff.number_of_symbols");
  DIFF_FIELD(coff_header->size_of_optional_header, "coff.size_of_optional_header");
  DIFF_FIELD(coff_header->characteristics, "coff.characteristics");
}

static void print_optional_diff(pe_t *first_pe, pe_t *second_pe, bool colorize)
{
  if (first_pe->type == MAGIC_32BIT)
  {
    print_optional32_diff((pe32_t *)first_pe, (pe32_t *)second_pe, colorize);
    return;
  }

  print_optional64_diff((pe64_t *)first_pe, (pe64_t *)second_pe, colorize);
}

static void print_optional32_diff(pe32_t *first_pe, pe32_t *second_pe, bool colorize)
{
  DIFF_FIELD(optional_header->magic, "optional.magic");
  DIFF_FIELD(optional_header->major_linker_version, "optional.major_linker_version");
  DIFF_FIELD(optional_header->minor_linker_version, "optional.minor_linker_version");
  DIFF_FIELD(optional_header->size_of_code, "optional.size_of_code");
  DIFF_FIELD(optional_header->size_of_initialized_data, "optional.size_of_initialized_data");
  DIFF_FIELD(optional_header->size_of_unitialized_data, "optional.size_of_unitialized_data");
  DIFF_FIELD(optional_header->entry_point, "optional.entry_point");
  DIFF_FIELD(optional_header->base_of_code, "optional.base_of_code");

  if (first_pe->type != second_pe->type)
  {
    return;
  }

  DIFF_FIELD(optional_header->base_of_data, "optional.base_of_data");

  DIFF_FIELD(optional_header->image_base, "optional.image_base");
  DIFF_FIELD(optional_header->section_alignment, "optional.section_alignment");
  DIFF_FIELD(optional_header->file_alignment, "optional.file_alignment");
  DIFF_FIELD(optional_header->major_os_version, "optional.major_os_version");
  DIFF_FIELD(optional_header->minor_os_version, "optional.minor_os_version");
  DIFF_FIELD(optional_header->major_image_version, "optional.major_image_version");
  DIFF_FIELD(optional_header->minor_image_version, "optional.minor_image_version");
  DIFF_FIELD(optional_header->major_subsystem_version, "optional.major_subsystem_version");
  DIFF_FIELD(optional_header->minor_subsystem_version, "optional.minor_subsystem_version");
  DIFF_FIELD(optional_header->win32_version_value, "optional.win32_version_value");
  DIFF_FIELD(optional_header->size_of_image, "optional.size_of_image");
  DIFF_FIELD(optional_header->size_of_headers, "optional.size_of_headers");
  DIFF_FIELD(optional_header->checksum, "optional.checksum");
  DIFF_FIELD(optional_header->subsystem, "optional.subsystem");
  DIFF_FIELD(optional_header->dll_characteristics, "optional.dll_characteristics");
  DIFF_FIELD(optional_header->size_of_stack_reserve, "optional.size_of_stack_reserve");
  DIFF_FIELD(optional_header->size_of_stack_commit, "optional.size_of_stack_commit");
  DIFF_FIELD(optional_header->size_of_head_reserve, "optional.size_of_head_reserve");
  DIFF_FIELD(optional_header->size_of_head_commit, "optional.size_of_head_commit");
  DIFF_FIELD(optional_header->loader_flags, "optional.loader_flags");
  DIFF_FIELD(optional_header->number_of_rva_and_sizes, "optional.number_of_rva_and_sizes");

  DIFF_DATA_DIRECTORY(export_table);
  DIFF_DATA_DIRECTORY(import_table);
  DIFF_DATA_DIRECTORY(resource_table);
  DIFF_DATA_DIRECTORY(exception_table);
  DIFF_DATA_DIRECTORY(certificate_table);
  DIFF_DATA_DIRECTORY(base_relocation_table);
  DIFF_DATA_DIRECTORY(debug);
  DIFF_DATA_DIRECTORY(architecture);
  DIFF_DATA_DIRECTORY(global_ptr);
  DIFF_DATA_DIRECTORY(tls_table);
  DIFF_DATA_DIRECTORY(load_config_table);
  DIFF_DATA_DIRECTORY(bound_import);
  DIFF_DATA_DIRECTORY(iat);
  DIFF_DATA_DIRECTORY(delay_import_descriptor);
  DIFF_DATA_DIRECTORY(clr_runtime_header);
}

static void print_optional64_diff(pe64_t *first_pe, pe64_t *second_pe, bool colorize)
{
  DIFF_FIELD(optional_header->magic, "optional.magic");
  DIFF_FIELD(optional_header->major_linker_version, "optional.major_linker_version");
  DIFF_FIELD(optional_header->minor_linker_version, "optional.minor_linker_version");
  DIFF_FIELD(optional_header->size_of_code, "optional.size_of_code");
  DIFF_FIELD(optional_header->size_of_initialized_data, "optional.size_of_initialized_data");
  DIFF_FIELD(optional_header->size_of_unitialized_data, "optional.size_of_unitialized_data");
  DIFF_FIELD(optional_header->entry_point, "optional.entry_point");
  DIFF_FIELD(optional_header->base_of_code, "optional.base_of_code");

  if (first_pe->type != second_pe->type)
  {
    return;
  }

  DIFF_FIELD(optional_header->image_base, "optional.image_base");
  DIFF_FIELD(optional_header->section_alignment, "optional.section_alignment");
  DIFF_FIELD(optional_header->file_alignment, "optional.file_alignment");
  DIFF_FIELD(optional_header->major_os_version, "optional.major_os_version");
  DIFF_FIELD(optional_header->minor_os_version, "optional.minor_os_version");
  DIFF_FIELD(optional_header->major_image_version, "optional.major_image_version");
  DIFF_FIELD(optional_header->minor_image_version, "optional.minor_image_version");
  DIFF_FIELD(optional_header->major_subsystem_version, "optional.major_subsystem_version");
  DIFF_FIELD(optional_header->minor_subsystem_version, "optional.minor_subsystem_version");
  DIFF_FIELD(optional_header->win32_version_value, "optional.win32_version_value");
  DIFF_FIELD(optional_header->size_of_image, "optional.size_of_image");
  DIFF_FIELD(optional_header->size_of_headers, "optional.size_of_headers");
  DIFF_FIELD(optional_header->checksum, "optional.checksum");
  DIFF_FIELD(optional_header->subsystem, "optional.subsystem");
  DIFF_FIELD(optional_header->dll_characteristics, "optional.dll_characteristics");
  DIFF_FIELD(optional_header->size_of_stack_reserve, "optional.size_of_stack_reserve");
  DIFF_FIELD(optional_header->size_of_stack_commit, "optional.size_of_stack_commit");
  DIFF_FIELD(optional_header->size_of_head_reserve, "optional.size_of_head_reserve");
  DIFF_FIELD(optional_header->size_of_head_commit, "optional.size_of_head_commit");
  DIFF_FIELD(optional_header->loader_flags, "optional.loader_flags");
  DIFF_FIELD(optional_header->number_of_rva_and_sizes, "optional.number_of_rva_and_sizes");

  DIFF_DATA_DIRECTORY(export_table);
  DIFF_DATA_DIRECTORY(import_table);
  DIFF_DATA_DIRECTORY(resource_table);
  DIFF_DATA_DIRECTORY(exception_table);
  DIFF_DATA_DIRECTORY(certificate_table);
  DIFF_DATA_DIRECTORY(base_relocation_table);
  DIFF_DATA_DIRECTORY(debug);
  DIFF_DATA_DIRECTORY(architecture);
  DIFF_DATA_DIRECTORY(global_ptr);
  DIFF_DATA_DIRECTORY(tls_table);
  DIFF_DATA_DIRECTORY(load_config_table);
  DIFF_DATA_DIRECTORY(bound_import);
  DIFF_DATA_DIRECTORY(iat);
  DIFF_DATA_DIRECTORY(delay_import_descriptor);
  DIFF_DATA_DIRECTORY(clr_runtime_header);
}

static void print_section_diff(pe_t *first_pe, pe_t *second_pe, unsigned int section, bool colorize)
{
  if (strcmp(first_pe->section_header[section]->name, second_pe->section_header[section]->name))
  {
    char fullname[48];
    sprintf(fullname, "section.%d.name", section);
    print_string_field(fullname,
                       first_pe->section_header[section]->name,
                       second_pe->section_header[section]->name,
                       colorize);
  }

  DIFF_SECTION_FIELD(section, virtual_size);
  DIFF_SECTION_FIELD(section, virtual_address);
  DIFF_SECTION_FIELD(section, size_of_raw_data);
  DIFF_SECTION_FIELD(section, pointer_to_raw_data);
  DIFF_SECTION_FIELD(section, pointer_to_relocations);
  DIFF_SECTION_FIELD(section, pointer_to_line_numbers);
  DIFF_SECTION_FIELD(section, number_of_relocations);
  DIFF_SECTION_FIELD(section, number_of_line_numbers);
  DIFF_SECTION_FIELD(section, characteristics);
}

static void print_dump_diff(pe_t *first_pe, pe_t *second_pe, unsigned int section, bool colorize)
{
  bool first_print = true;

  if (section > first_pe->number_of_sections || section > second_pe->number_of_sections)
  {
    return;
  }

  pe_section_header_t *first_section = first_pe->section_header[section];
  unsigned char first_data[16];
  unsigned char second_data[16];
  uint32_t offset = first_section->pointer_to_raw_data;
  uint32_t final_offset = first_section->pointer_to_raw_data + first_section->size_of_raw_data;

  pe_seek(first_pe, offset);
  pe_seek(second_pe, offset);
  for (; offset < final_offset; offset += DUMP_BLOCK_SIZE)
  {
    size_t count = first_section->size_of_raw_data - offset;
    count = (count < DUMP_BLOCK_SIZE)
                ? count
                : DUMP_BLOCK_SIZE;

    if (fread(first_data, 1, count, first_pe->file) < count)
    {
      goto read_file_error;
    }

    if (fread(second_data, 1, count, second_pe->file) < count)
    {
      goto read_file_error;
    }

    if (!memcmp(first_data, second_data, count))
    {
      // If the content is equal, do nothing
      continue;
    }

    if (first_print)
    {
      // Only print "header" if has any difference on the section
      printf("@section %u\n", section);
      first_print = false;
    }

    print_data_diff(offset, first_data, second_data, count, colorize);
  }

  return;

read_file_error:
  perror("diff error");
  exit(EXIT_FAILURE);
}

#define ASCII_MAXIMUM_CHAR_SIZE (sizeof(C_MODIFIED) + sizeof(C_NORMAL) + 1)
#define DUMP_MAXIMUM_BYTE_SIZE (sizeof(C_MODIFIED) + sizeof(C_NORMAL) + 3)

static void print_data_diff(uint32_t offset, unsigned char *first_data, unsigned char *second_data, size_t size, bool colorize)
{
  int ascii_original_index = 0;
  int ascii_modified_index = 0;
  int dump_original_index = 0;
  int dump_modified_index = 0;
  char ascii_original[size * ASCII_MAXIMUM_CHAR_SIZE];
  char ascii_modified[size * ASCII_MAXIMUM_CHAR_SIZE];
  char dump_original[size * DUMP_MAXIMUM_BYTE_SIZE];
  char dump_modified[size * DUMP_MAXIMUM_BYTE_SIZE];

  for (size_t i = 0; i < size; i++)
  {
    if (!colorize || first_data[i] == second_data[i])
    {
      dump_original_index += sprintf(dump_original + dump_original_index, "%02x ", first_data[i]);
      dump_modified_index += sprintf(dump_modified + dump_modified_index, "%02x ", second_data[i]);

      ascii_original[ascii_original_index++] = graphchar(first_data[i]);
      ascii_modified[ascii_modified_index++] = graphchar(second_data[i]);
      ascii_original[ascii_original_index] = '\0';
      ascii_modified[ascii_modified_index] = '\0';
      continue;
    }

    dump_original_index += sprintf(dump_original + dump_original_index, C_ORIGINAL "%02x " C_NORMAL, first_data[i]);
    dump_modified_index += sprintf(dump_modified + dump_modified_index, C_MODIFIED "%02x " C_NORMAL, second_data[i]);

    ascii_original_index += sprintf(ascii_original + ascii_original_index, C_ORIGINAL "%c" C_NORMAL, graphchar(first_data[i]));
    ascii_modified_index += sprintf(ascii_modified + ascii_modified_index, C_MODIFIED "%c" C_NORMAL, graphchar(second_data[i]));
  }

  printf("-0x%x %s |%s|\n", offset, dump_original, ascii_original);
  printf("+0x%x %s |%s|\n", offset, dump_modified, ascii_modified);
}
