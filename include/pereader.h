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

FILE *pe_open(char *filename);
pe_t *pe_parse(FILE *executable);
void pe_write_header(pe_t *pe);
void pe_seek(pe_t *pe, long int offset);

void pe_show_type(pe_t *pe);
void pe_show_coff_characteristics(pe_t *pe, bool verbose);
void pe_show_coff(pe_t *pe, bool verbose);
void pe32_show_optional_header(pe_t *pe);
void pe64_show_optional_header(pe_t *pe);
void pe_show_section_header(pe_t *pe, unsigned int section_number);
void pe_show_all_section_headers(pe_t *pe);

uint32_t pe_update_entrypoint(pe_t *pe, uint32_t address);
int64_t pe_offset_to_vaddress(pe_t *pe, uint32_t offset);
uint64_t pe_image_base(pe_t *pe);

int pe_search_address_section(pe_t *pe, uint32_t address);
int pe_search_entrypoint_section(pe_t *pe);
pe_block_t pe_search_biggest_zero_sequence_on_section(pe_t *pe, unsigned int section);
pe_block_t pe_search_biggest_zero_sequence(pe_t *pe);

#endif /* _PEREADER_H */
