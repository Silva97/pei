#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "pe.h"
#include "pereader.h"

#define SET_NUMBER_FIELD(structure, name, field, operator, value)    \
  if (!strcmp(name, #field))                                         \
  {                                                                  \
    structure->field = set_field(structure->field, operator, value); \
    return true;                                                     \
  }

#define SET_STRING_FIELD(structure, name, field, max_size, value) \
  if (!strcmp(name, #field))                                      \
  {                                                               \
    strncpy(structure->field, value, max_size);                   \
    return true;                                                  \
  }

#define SET_FIELD_DATA_DIRECTORY(structure, name, field, subfield, operator, value)                    \
  if (!strcmp(name, #field))                                                                           \
  {                                                                                                    \
    if (!strcmp(subfield, "virtual_address"))                                                          \
    {                                                                                                  \
      structure->field.virtual_address = set_field(structure->field.virtual_address, operator, value); \
    }                                                                                                  \
    else if (!strcmp(subfield, "size"))                                                                \
    {                                                                                                  \
      structure->field.size = set_field(structure->field.size, operator, value);                       \
    }                                                                                                  \
    else                                                                                               \
    {                                                                                                  \
      return false;                                                                                    \
    }                                                                                                  \
    return true;                                                                                       \
  }

static int64_t set_field(uint64_t original, pe_operator_t operator, int64_t value)
{
  switch (operator)
  {
  case OP_EQUAL:
    return value;
  case OP_OR_EQUAL:
    return original | value;
  case OP_AND_EQUAL:
    return original & value;
  default:
    return original;
  }
}

bool pe_set_field(pe_t *pe, char *field_string, pe_operator_t operator, char * value)
{
  char *structure = strtok(field_string, ".");
  char *field = strtok(NULL, ".");
  if (!structure || !field)
  {
    return false;
  }

  if (!strcmp(structure, "coff"))
  {
    return pe_set_coff_field(pe, field, operator, value);
  }

  if (!strcmp(structure, "section"))
  {
    int section;
    if (sscanf(field, "%d", &section) != 1)
    {
      return false;
    }

    field = strtok(NULL, ".");
    return pe_set_section_field(pe, section, field, operator, value);
  }

  if (!strcmp(structure, "optional"))
  {
    return pe_set_optional_field(pe, field, operator, value);
  }

  return false;
}

bool pe_set_coff_field(pe_t *pe, char *field, pe_operator_t operator, char * value)
{
  int64_t number = 0;
  sscanf(value, "%lli", &number);

  SET_NUMBER_FIELD(pe->coff_header, field, machine, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, number_of_sections, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, time_date_stamp, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, pointer_to_symbol_table, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, number_of_symbols, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, size_of_optional_header, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, characteristics, operator, number);

  return false;
}

bool pe_set_section_field(pe_t *pe, unsigned int section, char *field, pe_operator_t operator, char * value)
{
  int64_t number = 0;
  sscanf(value, "%lli", &number);

  SET_STRING_FIELD(pe->section_header[section], field, name, SECTION_FIELD_NAME_SIZE, value);
  SET_NUMBER_FIELD(pe->section_header[section], field, virtual_size, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, virtual_address, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, size_of_raw_data, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, pointer_to_raw_data, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, pointer_to_relocations, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, pointer_to_line_numbers, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, number_of_relocations, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, number_of_line_numbers, operator, number);
  SET_NUMBER_FIELD(pe->section_header[section], field, characteristics, operator, number);

  return false;
}

bool pe_set_optional_field(pe_t *pe, char *field, pe_operator_t operator, char * value)
{
  if (pe->type == MAGIC_32BIT)
  {
    return pe32_set_optional_field((pe32_t *)pe, field, operator, value);
  }

  return pe64_set_optional_field((pe64_t *)pe, field, operator, value);
}

bool pe32_set_optional_field(pe32_t *pe, char *field, pe_operator_t operator, char * value)
{
  int64_t number = 0;
  sscanf(value, "%lli", &number);

  SET_NUMBER_FIELD(pe->optional_header, field, magic, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_linker_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_linker_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_code, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_initialized_data, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_unitialized_data, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, entry_point, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, base_of_code, operator, number);

  SET_NUMBER_FIELD(pe->optional_header, field, base_of_data, operator, number);

  SET_NUMBER_FIELD(pe->optional_header, field, image_base, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, section_alignment, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, file_alignment, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_os_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_os_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_image_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_image_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_subsystem_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_subsystem_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, win32_version_value, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_image, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_headers, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, checksum, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, subsystem, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, dll_characteristics, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_stack_reserve, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_stack_commit, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_head_reserve, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_head_commit, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, loader_flags, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, number_of_rva_and_sizes, operator, number);

  // We assume that this function always will be called by pe_get_field() on
  // a executable single-threaded. This code will broken if it is not true. :)
  char *dir_field = strtok(NULL, ".");
  if (!dir_field)
  {
    return false;
  }

  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, export_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, import_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, resource_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, exception_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, certificate_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, base_relocation_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, debug, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, architecture, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, global_ptr, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, tls_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, load_config_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, bound_import, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, iat, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, delay_import_descriptor, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, clr_runtime_header, dir_field, operator, number);

  return false;
}

bool pe64_set_optional_field(pe64_t *pe, char *field, pe_operator_t operator, char * value)
{
  int64_t number = 0;
  sscanf(value, "%lli", &number);

  SET_NUMBER_FIELD(pe->optional_header, field, magic, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_linker_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_linker_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_code, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_initialized_data, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_unitialized_data, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, entry_point, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, base_of_code, operator, number);

  SET_NUMBER_FIELD(pe->optional_header, field, image_base, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, section_alignment, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, file_alignment, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_os_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_os_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_image_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_image_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, major_subsystem_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, minor_subsystem_version, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, win32_version_value, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_image, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_headers, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, checksum, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, subsystem, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, dll_characteristics, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_stack_reserve, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_stack_commit, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_head_reserve, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, size_of_head_commit, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, loader_flags, operator, number);
  SET_NUMBER_FIELD(pe->optional_header, field, number_of_rva_and_sizes, operator, number);

  // We assume that this function always will be called by pe_get_field() on
  // a executable single-threaded. This code will broken if it is not true. :)
  char *dir_field = strtok(NULL, ".");
  if (!dir_field)
  {
    return false;
  }

  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, export_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, import_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, resource_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, exception_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, certificate_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, base_relocation_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, debug, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, architecture, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, global_ptr, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, tls_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, load_config_table, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, bound_import, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, iat, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, delay_import_descriptor, dir_field, operator, number);
  SET_FIELD_DATA_DIRECTORY(pe->optional_header, field, clr_runtime_header, dir_field, operator, number);

  return false;
}
