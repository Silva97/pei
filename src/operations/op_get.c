#include "operations.h"
#include <stdlib.h>

void op_get(pe_t *pe, char *field_string, const char *format)
{
  char buff[32] = {0};

  if (!pe_get_field(pe, buff, field_string, format))
  {
    fprintf(stderr, "Get error: Field invalid on structure '%s'\n", field_string);
    exit(EXIT_FAILURE);
  }

  printf("%s\n", buff);
}
