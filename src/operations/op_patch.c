#include "win.h"
#include <stdlib.h>
#include <ctype.h>
#include "operations.h"

#define LINE_SIZE 255

#define show_error(line, line_number)                                                        \
  fprintf(stderr, "Patch error: Line %u has an invalid format:\n  %s\n", line_number, line); \
  exit(EXIT_FAILURE);

static bool patch_field(pe_t *pe, char *patch_line);
static bool patch_dump(pe_t *pe, char *patch_line);

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
        show_error(line, line_number);
      }
    }

    line_number++;
  }

  // Patch sections
  while (fgets(line, LINE_SIZE, patch))
  {
    line_number++;
    if (line[0] != '+')
    {
      continue;
    }

    if (!patch_dump(pe, line))
    {
      show_error(line, line_number);
    }
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

#define DUMP_BLOCK_SIZE 16
static bool patch_dump(pe_t *pe, char *patch_line)
{
  unsigned char block[DUMP_BLOCK_SIZE];
  char *data;
  char *dump;
  unsigned int block_index = 0;

  long int offset = strtol(patch_line, &dump, 16);
  if (patch_line == dump)
  {
    return false;
  }

  pe_seek(pe, offset);
  data = strtok(dump, " ");
  do
  {
    if (sscanf(data, "%02hhx", &block[block_index]) != 1)
    {
      break;
    }

    block_index++;
    if (block_index == DUMP_BLOCK_SIZE)
    {
      pe_write(pe, block, DUMP_BLOCK_SIZE);
      block_index = 0;
    }
  } while ((data = strtok(NULL, " ")));

  if (block_index > 0)
  {
    pe_write(pe, block, block_index);
  }

  return true;
}
