#include <string.h>
#include <stdbool.h>
#include "pe.h"
#include "pereader.h"

#define GET_FIELD(structure, name, field)    \
  if (!strcmp(name, #field))                 \
  {                                          \
    sprintf(buff, format, structure->field); \
    return true;                             \
  }

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
    if (!secstring || sscanf(secstring, "%d", &section) != 1)
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
    return pe32_get_optional_field(pe, buff, field, format);
  }

  return pe64_get_optional_field(pe, buff, field, format);
}

bool pe32_get_optional_field(pe_t *pe, char *buff, char *field, const char *format)
{
  pe32_optional_header_t *optional_header = pe->optional_header;

  GET_FIELD(optional_header, field, magic);
  GET_FIELD(optional_header, field, major_linker_version);
  GET_FIELD(optional_header, field, minor_linker_version);
  GET_FIELD(optional_header, field, size_of_code);
  GET_FIELD(optional_header, field, size_of_initialized_data);
  GET_FIELD(optional_header, field, size_of_unitialized_data);
  GET_FIELD(optional_header, field, entry_point);
  GET_FIELD(optional_header, field, base_of_code);

  GET_FIELD(optional_header, field, base_of_data);

  GET_FIELD(optional_header, field, image_base);
  GET_FIELD(optional_header, field, section_alignment);
  GET_FIELD(optional_header, field, file_alignment);
  GET_FIELD(optional_header, field, major_os_version);
  GET_FIELD(optional_header, field, minor_os_version);
  GET_FIELD(optional_header, field, major_image_version);
  GET_FIELD(optional_header, field, minor_image_version);
  GET_FIELD(optional_header, field, major_subsystem_version);
  GET_FIELD(optional_header, field, minor_subsystem_version);
  GET_FIELD(optional_header, field, win32_version_value);
  GET_FIELD(optional_header, field, size_of_image);
  GET_FIELD(optional_header, field, size_of_headers);
  GET_FIELD(optional_header, field, checksum);
  GET_FIELD(optional_header, field, subsystem);
  GET_FIELD(optional_header, field, dll_characteristics);
  GET_FIELD(optional_header, field, size_of_stack_reserve);
  GET_FIELD(optional_header, field, size_of_stack_commit);
  GET_FIELD(optional_header, field, size_of_head_reserve);
  GET_FIELD(optional_header, field, size_of_head_commit);
  GET_FIELD(optional_header, field, loader_flags);
  GET_FIELD(optional_header, field, number_of_rva_and_sizes);

  return false;
}

bool pe64_get_optional_field(pe_t *pe, char *buff, char *field, const char *format)
{
  pe64_optional_header_t *optional_header = pe->optional_header;

  GET_FIELD(optional_header, field, magic);
  GET_FIELD(optional_header, field, major_linker_version);
  GET_FIELD(optional_header, field, minor_linker_version);
  GET_FIELD(optional_header, field, size_of_code);
  GET_FIELD(optional_header, field, size_of_initialized_data);
  GET_FIELD(optional_header, field, size_of_unitialized_data);
  GET_FIELD(optional_header, field, entry_point);
  GET_FIELD(optional_header, field, base_of_code);

  GET_FIELD(optional_header, field, image_base);
  GET_FIELD(optional_header, field, section_alignment);
  GET_FIELD(optional_header, field, file_alignment);
  GET_FIELD(optional_header, field, major_os_version);
  GET_FIELD(optional_header, field, minor_os_version);
  GET_FIELD(optional_header, field, major_image_version);
  GET_FIELD(optional_header, field, minor_image_version);
  GET_FIELD(optional_header, field, major_subsystem_version);
  GET_FIELD(optional_header, field, minor_subsystem_version);
  GET_FIELD(optional_header, field, win32_version_value);
  GET_FIELD(optional_header, field, size_of_image);
  GET_FIELD(optional_header, field, size_of_headers);
  GET_FIELD(optional_header, field, checksum);
  GET_FIELD(optional_header, field, subsystem);
  GET_FIELD(optional_header, field, dll_characteristics);
  GET_FIELD(optional_header, field, size_of_stack_reserve);
  GET_FIELD(optional_header, field, size_of_stack_commit);
  GET_FIELD(optional_header, field, size_of_head_reserve);
  GET_FIELD(optional_header, field, size_of_head_commit);
  GET_FIELD(optional_header, field, loader_flags);
  GET_FIELD(optional_header, field, number_of_rva_and_sizes);

  return false;
}

bool pe_get_section_field(pe_t *pe, char *buff, unsigned int section, char *field, const char *format)
{
  GET_FIELD(pe->section_header[section], field, name);
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
