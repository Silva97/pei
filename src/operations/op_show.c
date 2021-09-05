#include <stdlib.h>
#include "operations.h"

#define INFO(info, expected) \
  (!strcmp(info, "all") || strchr(info, expected))

void op_show(pe_t *pe, char *info, int section, bool verbose)
{
  if (!strncmp(info, "dump", 4))
  {
    if (section < 0)
    {
      fputs("Show error: Section not specified. You can't dump all sections at same time.\n", stderr);
      exit(EXIT_FAILURE);
    }

    uint32_t offset = pe->section_header[section]->pointer_to_raw_data;

    if (info[4] == 'r')
    {
      pe_dump_raw(pe, offset, pe->section_header[section]->size_of_raw_data);
      return;
    }

    pe_dump(pe, offset, pe->section_header[section]->size_of_raw_data);
    return;
  }

  if (INFO(info, 'g'))
  {
    printf("--- General ---\n");
    pe_show_info(pe);
  }

  if (INFO(info, 'c'))
  {
    printf("--- COFF header ---\n");
    pe_show_coff(pe, verbose);
  }

  if (INFO(info, 'o'))
  {
    printf("--- Optional header ---\n");
    pe_show_optional_header(pe, verbose);
  }

  if (INFO(info, 'd'))
  {
    printf("--- Data directories ---\n");
    pe_show_data_directories(pe);
  }

  if (INFO(info, 's'))
  {
    if (section < 0)
    {
      pe_show_all_section_headers(pe, verbose);
    }
    else
    {
      printf("--- Section #%d ---\n", section);
      pe_show_section_header(pe, section, verbose);
    }
  }
}
