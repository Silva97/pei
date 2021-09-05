#include "tests.h"

test_t test_open_pe_executable(void)
{
  FILE *executable = pe_open(TEST_PE);
  METRIC_ASSERT(executable);

  fclose(executable);
  METRIC_TEST_OK();
}

test_t test_parse_pe_executable(void)
{
  pe_data_directory_t expected_architecture = {
      .virtual_address = 0,
      .size = 0,
  };

  FILE *executable = pe_open(TEST_PE);
  METRIC_ASSERT(executable);

  pe64_t *pe = (pe64_t *)pe_parse(executable);
  METRIC_ASSERT(pe);
  METRIC_ASSERT(pe->file == executable);

  // COFF header
  METRIC_ASSERT(pe->number_of_sections == pe->coff_header->number_of_sections);
  METRIC_ASSERT(pe->coff_header->machine == AMD64);
  METRIC_ASSERT(pe->coff_header->size_of_optional_header == sizeof(pe64_optional_header_t));

  // Optional header
  METRIC_ASSERT(pe->type == pe->optional_header->magic);
  METRIC_ASSERT(pe->optional_header->subsystem == WINDOWS_CUI);
  METRIC_ASSERT_ARRAY(&pe->optional_header->architecture, &expected_architecture, sizeof(pe_data_directory_t));

  // Section header
  METRIC_ASSERT_STRING(pe->section_header[0]->name, ".text");
  METRIC_ASSERT(pe->section_header[0]->characteristics & MEM_EXECUTE);

  pe_free((pe_t *)pe);
  METRIC_TEST_OK();
}

int main(void)
{
  METRIC_TEST(test_open_pe_executable);
  METRIC_TEST(test_parse_pe_executable);

  METRIC_TEST_END();
}
