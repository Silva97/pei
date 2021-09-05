#include "operations.h"
#include <stdlib.h>
#include <string.h>

void op_edit(pe_t *pe, char *field_string, char *operator, char * value)
{
  pe_operator_t op_value;
  if (!strcmp(operator, "="))
  {
    op_value = OP_EQUAL;
  }
  else if (!strcmp(operator, "|="))
  {
    op_value = OP_OR_EQUAL;
  }
  else if (!strcmp(operator, "&="))
  {
    op_value = OP_AND_EQUAL;
  }
  else
  {
    fprintf(stderr, "Edit error: Operator '%s' is invalid.\n", operator);
    exit(EXIT_FAILURE);
  }

  if (!pe_set_field(pe, field_string, op_value, value))
  {
    fprintf(stderr, "Edit error: Field invalid on structure '%s'\n\n", field_string);
    exit(EXIT_FAILURE);
  }

  pe_write_header(pe);
}
