#include <stdlib.h>
#include <string.h>
#include "pereader.h"

static void mem_error(void)
{
  perror("pe_parser: memory allocation error.");
  exit(EXIT_FAILURE);
}

pe_t *pe_parse(FILE *executable)
{
  long int last_position;
  pe_coff_header_t *coff_header;

  if (!executable)
  {
    return NULL;
  }

  coff_header = malloc(sizeof(pe_coff_header_t));
  if (!coff_header)
  {
    mem_error();
  }

  if (!fread(coff_header, sizeof(pe_coff_header_t), 1, executable))
  {
    free(coff_header);
    return NULL;
  }

  pe_t *pe = malloc(sizeof *pe + coff_header->number_of_sections * sizeof(pe_section_header_t *));
  if (!pe)
  {
    mem_error();
  }

  pe->coff_header = coff_header;
  pe->number_of_sections = coff_header->number_of_sections;

  // Checking the magic number to determinate the correct optional header struct size
  last_position = ftell(executable);
  if (!fread(&pe->type, sizeof pe->type, 1, executable))
  {
    goto free_and_return_null;
  }

  fseek(executable, last_position, SEEK_SET);
  size_t size;

  switch (pe->type)
  {
  case MAGIC_32BIT:
    size = sizeof(pe32_optional_header_t);
    break;
  case MAGIC_64BIT:
    size = sizeof(pe64_optional_header_t);
    break;
  default:
    goto free_and_return_null;
  }

  pe->optional_header = malloc(size);
  if (!pe->optional_header)
  {
    mem_error();
  }

  if (!fread(pe->optional_header, size, 1, executable))
  {
    free(pe->optional_header);
    goto free_and_return_null;
  }

  for (int i = 0; i < coff_header->number_of_sections; i++)
  {
    pe->section_header[i] = malloc(sizeof(pe_section_header_t));
    if (!pe->section_header[i])
    {
      mem_error();
    }

    if (!fread(pe->section_header[i], sizeof(pe_section_header_t), 1, executable))
    {
      goto free_and_return_null;
    }
  }

  pe->file = executable;
  return pe;

free_and_return_null:
  free(coff_header);
  free(pe);
  return NULL;
}
