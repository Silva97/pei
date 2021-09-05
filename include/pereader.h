#ifndef _PEREADER_H
#define _PEREADER_H

#include "win.h"

#include <stdio.h>
#include <stdbool.h>
#include "pe.h"

typedef struct pe_block
{
  uint64_t offset;
  uint64_t size;
  uint16_t section;
} pe_block_t;

typedef enum pe_operator
{
  OP_EQUAL,
  OP_OR_EQUAL,
  OP_AND_EQUAL,
} pe_operator_t;

FILE *pe_open(char *filename);
bool pe_check(FILE *executable);
pe_t *pe_parse(FILE *executable);
void pe_free(pe_t *pe);
void pe_write(pe_t *pe, void *data, size_t size);
void pe_write_header(pe_t *pe);
void pe_seek(pe_t *pe, long int offset);

bool pe_get_field(pe_t *pe, char *buff, char *field_string, const char *format);
bool pe_get_coff_field(pe_t *pe, char *buff, char *field, const char *format);
bool pe_get_optional_field(pe_t *pe, char *buff, char *field, const char *format);
bool pe32_get_optional_field(pe32_t *pe, char *buff, char *field, const char *format);
bool pe64_get_optional_field(pe64_t *pe, char *buff, char *field, const char *format);
bool pe_get_section_field(pe_t *pe, char *buff, unsigned int section, char *field, const char *format);

bool pe_set_field(pe_t *pe, char *field_string, pe_operator_t operator, char * value);
bool pe_set_coff_field(pe_t *pe, char *field, pe_operator_t operator, char * value);
bool pe_set_section_field(pe_t *pe, unsigned int section, char *field, pe_operator_t operator, char * value);
bool pe_set_optional_field(pe_t *pe, char *field, pe_operator_t operator, char * value);
bool pe32_set_optional_field(pe32_t *pe, char *field, pe_operator_t operator, char * value);
bool pe64_set_optional_field(pe64_t *pe, char *field, pe_operator_t operator, char * value);

void pe_dump(pe_t *pe, uint32_t offset, uint32_t size);
void pe_dump_raw(pe_t *pe, uint32_t offset, uint32_t size);
void pe_show_type(pe_t *pe);
void pe_show_info(pe_t *pe);
void pe_show_subsystem(pe_t *pe, bool verbose);
void pe_show_coff_machine(pe_t *pe, bool verbose);
void pe_show_coff_characteristics(pe_t *pe, bool verbose);
void pe_show_coff(pe_t *pe, bool verbose);
void pe_show_dll_characteristics(pe_t *pe, bool verbose);
void pe32_show_optional_header(pe32_t *pe, bool verbose);
void pe64_show_optional_header(pe64_t *pe, bool verbose);
void pe32_show_data_directories(pe32_t *pe);
void pe64_show_data_directories(pe64_t *pe);
void pe_show_data_directories(pe_t *pe);
void pe_show_optional_header(pe_t *pe, bool verbose);
void pe_show_section_characteristics(pe_t *pe, unsigned int section_number, bool verbose);
void pe_show_section_header(pe_t *pe, unsigned int section_number, bool verbose);
void pe_show_all_section_headers(pe_t *pe, bool verbose);

uint32_t pe_update_entrypoint(pe_t *pe, uint32_t address);
void pe_aslr(pe_t *pe, bool enable);
int64_t pe_offset_to_vaddress(pe_t *pe, uint32_t offset);
uint64_t pe_image_base(pe_t *pe);

int pe_search_address_section(pe_t *pe, uint32_t address);
int pe_search_entrypoint_section(pe_t *pe);
pe_block_t pe_search_biggest_zero_sequence_on_section(pe_t *pe, unsigned int section);
pe_block_t pe_search_biggest_zero_sequence(pe_t *pe);

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

#define GET_FIELD(structure, name, field)    \
  if (!strcmp(name, #field))                 \
  {                                          \
    sprintf(buff, format, structure->field); \
    return true;                             \
  }

#define GET_FIELD_DATA_DIRECTORY(structure, name, field, subfield) \
  if (!strcmp(name, #field))                                       \
  {                                                                \
    if (!strcmp(subfield, "virtual_address"))                      \
    {                                                              \
      sprintf(buff, format, structure->field.virtual_address);     \
    }                                                              \
    else if (!strcmp(subfield, "size"))                            \
    {                                                              \
      sprintf(buff, format, structure->field.size);                \
    }                                                              \
    else                                                           \
    {                                                              \
      return false;                                                \
    }                                                              \
    return true;                                                   \
  }

#endif /* _PEREADER_H */
