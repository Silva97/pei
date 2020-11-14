#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "pereader.h"
#include "operations.h"

void validate_operation(char *operation, char *expected_name);
void show_version_info();
void show_help();

#define show_error(mask, ...)                          \
  {                                                    \
    fprintf(stderr, "Error: " mask "\n", __VA_ARGS__); \
    exit(EXIT_FAILURE);                                \
  }

int main(int argc, char **argv)
{
  int section_number = -1;
  struct option options[] = {
      {"help", no_argument, NULL, 'h'},
      {"section", required_argument, NULL, 's'},
      {0, 0, 0, 0},
  };

  int c;
  int option_index;
  while ((c = getopt_long(argc, argv, "hs:", options, &option_index)) >= 0)
  {
    switch (c)
    {
    case 's':
      if (sscanf(optarg, "%d", &section_number) != 1)
      {
        show_error("'%s' is an invalid section number.", optarg);
      }
      break;
    case 'h':
      show_help();
      exit(EXIT_SUCCESS);
    default:
      exit(EXIT_FAILURE);
      break;
    }
  }

  // Check positional arguments <operation> and <executable>
  if (optind > argc - 2)
  {
    show_error("More %d positional arguments is required.\nSee help: pei -h", optind - argc + 2);
  }

  char *operation = argv[optind];
  char *filename = argv[optind + 1];
  FILE *executable = pe_open(filename);
  if (!executable)
  {
    show_error("File '%s' not found or isn't a PE32 or PE32+ executable.", filename);
  }

  pe_t *pe = pe_parse(executable);

  // Operations
  switch (operation[0])
  {
  case 'z':
    validate_operation(operation, "zeros");
    op_zeros(pe, section_number);
    break;
  }

  return 0;
}

void validate_operation(char *operation, char *expected_name)
{
  if (operation[1] && strcmp(operation, expected_name))
  {
    show_error("Operation '%s' is invalid. Did you mean '%s'?", operation, expected_name);
  }
}

void show_version_info()
{
  puts("Developed by Luiz Felipe <felipe.silva337@yahoo.com>\n"
       "Distributed under the MIT License.\n\n"

       "pei v1.0.0");
}

void show_help()
{
  show_version_info();
  puts("Tool for inject code and manipulate 64-bit (PE32+) and 32-bit (PE32)\n"
       "PE executables.\n\n"

       "USAGE\n"
       "  pei [options] <operation> <executable>\n"
       "    operation     Operation to do with the executable.\n"
       "    executable    PE32 or PE32+ executable file.\n\n"

       "OPTIONS\n"
       "  -h,--help       Show this help message\n"
       "  -f,--file       Read the code from the binary file. If not specified, the\n"
       "                  code will be read from stdin.\n"
       "  -s,--section    Do operation only on the specific section. Section is the\n"
       "                  number of the section. If this options is not specified,\n"
       "                  by default all sections will be affected by operation.\n\n"

       "OPERATIONS\n"
       "  z,zeros           Finds biggest zeroed block on sections of the executable.\n"
       "  i,inject          Injects code into the section or, if not specified, in the\n"
       "                    biggest zeroed block between all sections.\n"
       "                    When inject code, the section is marked as executable.\n");
}
