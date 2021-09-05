#include "win.h"
#include <string.h>
#include <stdbool.h>
#include "pe.h"
#include "pereader.h"

bool pe_get_field(pe_t *pe, char *buff, char *field_string, const char *format)
{
  unsigned int section = -1;
  char *structure = strtok(field_string, ".");
  if (!structure)
  {
    return false;
  }

  if (!strcmp(structure, "section"))
  {
    char *secstring = strtok(NULL, ".");
    if (!secstring || sscanf(secstring, "%u", &section) != 1)
    {
      return false;
    }

    char *field = strtok(NULL, ".");
    if (!field)
    {
      return false;
    }
    return pe_get_section_field(pe, buff, section, field, format);
  }

  char *field = strtok(NULL, ".");
  if (!field)
  {
    return false;
  }

  if (!strcmp(structure, "coff"))
  {
    return pe_get_coff_field(pe, buff, field, format);
  }

  if (!strcmp(structure, "optional"))
  {
    return pe_get_optional_field(pe, buff, field, format);
  }

  return false;
}

bool pe_get_coff_field(pe_t *pe, char *buff, char *field, const char *format)
{
  GET_FIELD(pe->coff_header, field, machine);
  GET_FIELD(pe->coff_header, field, number_of_sections);
  GET_FIELD(pe->coff_header, field, time_date_stamp);
  GET_FIELD(pe->coff_header, field, pointer_to_symbol_table);
  GET_FIELD(pe->coff_header, field, number_of_symbols);
  GET_FIELD(pe->coff_header, field, size_of_optional_header);
  GET_FIELD(pe->coff_header, field, characteristics);

  return false;
}

bool pe_get_optional_field(pe_t *pe, char *buff, char *field, const char *format)
{
  if (pe->type == MAGIC_32BIT)
  {
    return pe32_get_optional_field((pe32_t *)pe, buff, field, format);
  }

  return pe64_get_optional_field((pe64_t *)pe, buff, field, format);
}

bool pe32_get_optional_field(pe32_t *pe, char *buff, char *field, const char *format)
{
  GET_FIELD(pe->optional_header, field, magic);
  GET_FIELD(pe->optional_header, field, major_linker_version);
  GET_FIELD(pe->optional_header, field, minor_linker_version);
  GET_FIELD(pe->optional_header, field, size_of_code);
  GET_FIELD(pe->optional_header, field, size_of_initialized_data);
  GET_FIELD(pe->optional_header, field, size_of_unitialized_data);
  GET_FIELD(pe->optional_header, field, entry_point);
  GET_FIELD(pe->optional_header, field, base_of_code);

  GET_FIELD(pe->optional_header, field, base_of_data);

  GET_FIELD(pe->optional_header, field, image_base);
  GET_FIELD(pe->optional_header, field, section_alignment);
  GET_FIELD(pe->optional_header, field, file_alignment);
  GET_FIELD(pe->optional_header, field, major_os_version);
  GET_FIELD(pe->optional_header, field, minor_os_version);
  GET_FIELD(pe->optional_header, field, major_image_version);
  GET_FIELD(pe->optional_header, field, minor_image_version);
  GET_FIELD(pe->optional_header, field, major_subsystem_version);
  GET_FIELD(pe->optional_header, field, minor_subsystem_version);
  GET_FIELD(pe->optional_header, field, win32_version_value);
  GET_FIELD(pe->optional_header, field, size_of_image);
  GET_FIELD(pe->optional_header, field, size_of_headers);
  GET_FIELD(pe->optional_header, field, checksum);
  GET_FIELD(pe->optional_header, field, subsystem);
  GET_FIELD(pe->optional_header, field, dll_characteristics);
  GET_FIELD(pe->optional_header, field, size_of_stack_reserve);
  GET_FIELD(pe->optional_header, field, size_of_stack_commit);
  GET_FIELD(pe->optional_header, field, size_of_head_reserve);
  GET_FIELD(pe->optional_header, field, size_of_head_commit);
  GET_FIELD(pe->optional_header, field, loader_flags);
  GET_FIELD(pe->optional_header, field, number_of_rva_and_sizes);

  // We assume that this function always will be called by pe_get_field() on
  // a executable single-threaded. This code will broken if it is not true. :)
  char *dir_field = strtok(NULL, ".");
  if (!dir_field)
  {
    return false;
  }

  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, export_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, import_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, resource_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, exception_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, certificate_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, base_relocation_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, debug, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, architecture, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, global_ptr, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, tls_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, load_config_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, bound_import, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, iat, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, delay_import_descriptor, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, clr_runtime_header, dir_field);

  return false;
}

bool pe64_get_optional_field(pe64_t *pe, char *buff, char *field, const char *format)
{
  GET_FIELD(pe->optional_header, field, magic);
  GET_FIELD(pe->optional_header, field, major_linker_version);
  GET_FIELD(pe->optional_header, field, minor_linker_version);
  GET_FIELD(pe->optional_header, field, size_of_code);
  GET_FIELD(pe->optional_header, field, size_of_initialized_data);
  GET_FIELD(pe->optional_header, field, size_of_unitialized_data);
  GET_FIELD(pe->optional_header, field, entry_point);
  GET_FIELD(pe->optional_header, field, base_of_code);

  GET_FIELD(pe->optional_header, field, image_base);
  GET_FIELD(pe->optional_header, field, section_alignment);
  GET_FIELD(pe->optional_header, field, file_alignment);
  GET_FIELD(pe->optional_header, field, major_os_version);
  GET_FIELD(pe->optional_header, field, minor_os_version);
  GET_FIELD(pe->optional_header, field, major_image_version);
  GET_FIELD(pe->optional_header, field, minor_image_version);
  GET_FIELD(pe->optional_header, field, major_subsystem_version);
  GET_FIELD(pe->optional_header, field, minor_subsystem_version);
  GET_FIELD(pe->optional_header, field, win32_version_value);
  GET_FIELD(pe->optional_header, field, size_of_image);
  GET_FIELD(pe->optional_header, field, size_of_headers);
  GET_FIELD(pe->optional_header, field, checksum);
  GET_FIELD(pe->optional_header, field, subsystem);
  GET_FIELD(pe->optional_header, field, dll_characteristics);
  GET_FIELD(pe->optional_header, field, size_of_stack_reserve);
  GET_FIELD(pe->optional_header, field, size_of_stack_commit);
  GET_FIELD(pe->optional_header, field, size_of_head_reserve);
  GET_FIELD(pe->optional_header, field, size_of_head_commit);
  GET_FIELD(pe->optional_header, field, loader_flags);
  GET_FIELD(pe->optional_header, field, number_of_rva_and_sizes);

  // We assume that this function always will be called by pe_get_field() on
  // a executable single-threaded. This code will broken if it is not true. :)
  char *dir_field = strtok(NULL, ".");
  if (!dir_field)
  {
    return false;
  }

  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, export_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, import_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, resource_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, exception_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, certificate_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, base_relocation_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, debug, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, architecture, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, global_ptr, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, tls_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, load_config_table, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, bound_import, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, iat, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, delay_import_descriptor, dir_field);
  GET_FIELD_DATA_DIRECTORY(pe->optional_header, field, clr_runtime_header, dir_field);

  return false;
}

bool pe_get_section_field(pe_t *pe, char *buff, unsigned int section, char *field, const char *format)
{
  char name[SECTION_FIELD_NAME_SIZE + 1];
  if (!strcmp(field, "name"))
  {
    strncpy(name, pe->section_header[section]->name, SECTION_FIELD_NAME_SIZE);
    name[SECTION_FIELD_NAME_SIZE] = '\0';

    sprintf(buff, format, name);
    return true;
  }

  GET_FIELD(pe->section_header[section], field, virtual_size);
  GET_FIELD(pe->section_header[section], field, virtual_address);
  GET_FIELD(pe->section_header[section], field, size_of_raw_data);
  GET_FIELD(pe->section_header[section], field, pointer_to_raw_data);
  GET_FIELD(pe->section_header[section], field, pointer_to_relocations);
  GET_FIELD(pe->section_header[section], field, pointer_to_line_numbers);
  GET_FIELD(pe->section_header[section], field, number_of_relocations);
  GET_FIELD(pe->section_header[section], field, number_of_line_numbers);
  GET_FIELD(pe->section_header[section], field, characteristics);

  return false;
}
