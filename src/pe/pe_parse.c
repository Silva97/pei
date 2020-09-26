#include <stdlib.h>
#include <string.h>
#include "pereader.h"

pe_t *pe_parse(FILE *executable)
{
    long int last_position;

    if (!executable)
    {
        return NULL;
    }

    pe_t *pe = malloc(sizeof *pe);
    pe->coff_header = malloc(sizeof(pe_coff_header_t));

    fread(pe->coff_header, sizeof(pe_coff_header_t), 1, executable);

    // Checking the magic number to determinate the correct optional header struct size
    last_position = ftell(executable);
    fread(&pe->type, sizeof pe->type, 1, executable);
    fseek(executable, last_position, SEEK_SET);

    switch (pe->type)
    {
    case PE_MAGIC_32BIT:
        pe->optional_header = malloc(sizeof(pe32_optional_header_t));
        fread(pe->optional_header, sizeof(pe32_optional_header_t), 1, executable);
        break;
    case PE_MAGIC_64BIT:
        pe->optional_header = malloc(sizeof(pe64_optional_header_t));
        fread(pe->optional_header, sizeof(pe64_optional_header_t), 1, executable);
        break;
    default:
        return NULL;
    }

    pe->section_header = malloc(sizeof(pe_section_header_t));
    fread(pe->section_header, sizeof(pe_section_header_t), 1, executable);
    return pe;
}
