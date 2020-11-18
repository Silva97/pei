#ifndef _PEREADER_H
#define _PEREADER_H

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

void pe_dump(pe_t *pe, uint32_t offset, uint32_t size);
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
void pe_disable_aslr(pe_t *pe);
int64_t pe_offset_to_vaddress(pe_t *pe, uint32_t offset);
uint64_t pe_image_base(pe_t *pe);

int pe_search_address_section(pe_t *pe, uint32_t address);
int pe_search_entrypoint_section(pe_t *pe);
pe_block_t pe_search_biggest_zero_sequence_on_section(pe_t *pe, unsigned int section);
pe_block_t pe_search_biggest_zero_sequence(pe_t *pe);

#endif /* _PEREADER_H */
