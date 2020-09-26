#include <stdio.h>
#include "pereader.h"

int main(int argc, char **argv)
{
  pe_t *pe = pe_parse(pe_open(argv[1]));
  if (!pe)
  {
    fprintf(stderr, "File '%s' is not a valid 32-bit or 64-bit PE executable.\n", argv[1]);
    return 1;
  }

  pe_show_type(pe);

  puts("### COFF header ###\n");
  pe_show_coff(pe);

  puts("\n### Optional header ###\n");
  if (pe->type == PE_MAGIC_32BIT)
  {
    pe32_show_optional_header(pe);
  }
  else
  {
    pe64_show_optional_header(pe);
  }

  return 0;
}
