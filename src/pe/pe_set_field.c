#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "pe.h"
#include "pereader.h"

#define SET_NUMBER_FIELD(structure, name, field, operator, value)    \
  if (!strcmp(name, #field))                                         \
  {                                                                  \
    printf("%s->%s\n = %lx\n", #structure, #field, value);           \
    structure->field = set_field(structure->field, operator, value); \
    return true;                                                     \
  }

static int64_t set_field(uint64_t original, pe_operator_t operator, int64_t value)
{
  switch (operator)
  {
  case OP_EQUAL:
    return value;
  case OP_OR_EQUAL:
    return original | value;
  case OP_AND_EQUAL:
    return original & value;
  default:
    return original;
  }
}

bool pe_set_field(pe_t *pe, char *field_string, pe_operator_t operator, char * value)
{
  char *structure = strtok(field_string, ".");
  char *field = strtok(NULL, ".");
  if (!structure || !field)
  {
    return false;
  }

  if (!strcmp(structure, "coff"))
  {
    return pe_set_coff_field(pe, field, operator, value);
  }

  return false;
}

bool pe_set_coff_field(pe_t *pe, char *field, pe_operator_t operator, char * value)
{
  int64_t number = 0;
  sscanf(value, "%li", &number);

  SET_NUMBER_FIELD(pe->coff_header, field, machine, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, number_of_sections, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, time_date_stamp, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, pointer_to_symbol_table, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, number_of_symbols, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, size_of_optional_header, operator, number);
  SET_NUMBER_FIELD(pe->coff_header, field, characteristics, operator, number);

  return false;
}
