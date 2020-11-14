#include <stdlib.h>
#include <string.h>
#include "pereader.h"

pe_t *pe_parse(FILE *executable)
{
  long int last_position;
  pe_coff_header_t *coff_header;

  if (!executable)
  {
    return NULL;
  }

  coff_header = malloc(sizeof(pe_coff_header_t));
  fread(coff_header, sizeof(pe_coff_header_t), 1, executable);

  pe_t *pe = malloc(sizeof *pe + coff_header->number_of_sections * sizeof(pe_section_header_t *));
  pe->coff_header = coff_header;

  // Checking the magic number to determinate the correct optional header struct size
  last_position = ftell(executable);
  fread(&pe->type, sizeof pe->type, 1, executable);
  fseek(executable, last_position, SEEK_SET);

  switch (pe->type)
  {
  case MAGIC_32BIT:
    pe->optional_header = malloc(sizeof(pe32_optional_header_t));
    fread(pe->optional_header, sizeof(pe32_optional_header_t), 1, executable);
    break;
  case MAGIC_64BIT:
    pe->optional_header = malloc(sizeof(pe64_optional_header_t));
    fread(pe->optional_header, sizeof(pe64_optional_header_t), 1, executable);
    break;
  default:
    return NULL;
  }

  for (int i = 0; i < coff_header->number_of_sections; i++)
  {
    pe->section_header[i] = malloc(sizeof(pe_section_header_t));
    fread(pe->section_header[i], sizeof(pe_section_header_t), 1, executable);
  }

  pe->file = executable;
  return pe;
}
