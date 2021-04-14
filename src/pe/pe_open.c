#include "win.h"
#include <string.h>
#include <stdbool.h>
#include "pereader.h"

FILE *pe_open(char *filename)
{
  FILE *executable = fopen(filename, "r+b");
  if (!executable)
  {
    return NULL;
  }

  if (!pe_check(executable))
  {
    fclose(executable);
    return NULL;
  }

  return executable;
}

bool pe_check(FILE *executable)
{
  char signature[PE_SIGNATURE_SIZE];
  int32_t signature_address;

  fseek(executable, PE_SIGNATURE_ADDRESS_OFFSET, SEEK_SET);
  if (!fread(&signature_address, sizeof signature_address, 1, executable))
  {
    return false;
  }

  fseek(executable, signature_address, SEEK_SET);
  if (!fread(signature, PE_SIGNATURE_SIZE, 1, executable))
  {
    return false;
  }

  return !memcmp(signature, PE_SIGNATURE, PE_SIGNATURE_SIZE);
}
