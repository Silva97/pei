#ifndef _PEREADER_H
#define _PEREADER_H

#include <stdio.h>
#include "pe.h"

FILE *pe_open(char *filename);
pe_t *pe_parse(FILE *executable);

void pe_show_type(pe_t *pe);
void pe_show_coff(pe_t *pe);
void pe32_show_optional_header(pe_t *pe);
void pe64_show_optional_header(pe_t *pe);

#endif /* _PEREADER_H */
