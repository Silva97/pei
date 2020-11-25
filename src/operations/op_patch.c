#include <stdlib.h>
#include <ctype.h>
#include "operations.h"

#define LINE_SIZE 255

static bool patch_field(pe_t *pe, char *patch_line);

void op_patch(pe_t *pe, char *filename)
{
  char line[LINE_SIZE + 1];
  FILE *patch;

  if (filename)
  {
    patch = fopen(filename, "r");
    if (!patch)
    {
      fprintf(stderr, "File '%s' not found.\n", filename);
      exit(EXIT_FAILURE);
    }
  }
  else
  {
    patch = stdin;
  }

  // Patch fields
  unsigned int line_number = 1;
  while (fgets(line, LINE_SIZE, patch) && line[0] != '@')
  {
    if (isalpha(line[0]))
    {
      if (!patch_field(pe, line))
      {
        fprintf(stderr, "Patch error: Line %u has an invalid format:\n  %s\n", line_number, line);
        exit(EXIT_FAILURE);
      }
    }

    line_number++;
  }

  if (filename)
  {
    fclose(patch);
  }
  pe_write_header(pe);
}

static bool patch_field(pe_t *pe, char *patch_line)
{
  char field[256];
  char value[65];

  if (sscanf(patch_line, "%255s %*s %64s", field, value) != 2)
  {
    return false;
  }

  return pe_set_field(pe, field, OP_EQUAL, value);
}
