#include <string.h>
#include "pereader.h"

FILE *pe_open(char *filename)
{
  char *signature[PE_SIGNATURE_SIZE];
  int32_t signature_address;

  FILE *executable = fopen(filename, "rb");

  fseek(executable, PE_SIGNATURE_ADDRESS_OFFSET, SEEK_SET);
  fread(&signature_address, sizeof signature_address, 1, executable);
  fseek(executable, signature_address, SEEK_SET);
  fread(signature, PE_SIGNATURE_SIZE, 1, executable);

  if (memcmp(signature, PE_SIGNATURE, PE_SIGNATURE_SIZE))
  {
    return NULL;
  }

  return executable;
}
