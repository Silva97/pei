#include "operations.h"
#include <stdlib.h>

static const char *status_name[] = {
    "disabled",
    "enabled",
};

void op_aslr(pe_t *pe, const char *status)
{
  bool current_status;

  if (!status)
  {
    if (pe->type == MAGIC_32BIT)
    {
      pe32_optional_header_t *optional_header = pe->optional_header;
      current_status = optional_header->dll_characteristics & DYNAMIC_BASE;
    }
    else
    {
      pe64_optional_header_t *optional_header = pe->optional_header;
      current_status = optional_header->dll_characteristics & DYNAMIC_BASE;
    }

    printf("ASLR is currently %s.\n", status_name[current_status]);
    return;
  }

  if (!strcmp(status, "on"))
  {
    pe_aslr(pe, true);
    pe_write_header(pe);
    return;
  }

  if (!strcmp(status, "off"))
  {
    pe_aslr(pe, false);
    pe_write_header(pe);
    return;
  }

  fprintf(stderr, "ASLR error: Status '%s' is invalid.\n", status);
  exit(EXIT_FAILURE);
}
