#include "tests.h"

test_t test_pe_write_header(void)
{
  PE_TEST_INIT();

  // Edit fields
  pe64->coff_header->time_date_stamp = 0x1234;
  pe64->optional_header->size_of_code = 0xaabb;
  strcpy(pe64->section_header[3]->name, ".new");
  pe64->section_header[5]->virtual_address = 0xdeafbeef;
  pe_write_header(pe);
  pe_free(pe);

  // Reopen file
  pe64 = (pe64_t *)pe_parse(pe_open(TEST_PE));
  METRIC_ASSERT(pe64);

  // Checking values
  METRIC_ASSERT(pe64->coff_header->time_date_stamp == 0x1234);
  METRIC_ASSERT(pe64->optional_header->size_of_code == 0xaabb);
  METRIC_ASSERT_STRING(pe64->section_header[3]->name, ".new");
  METRIC_ASSERT(pe64->section_header[5]->virtual_address == 0xdeafbeef);

  PE_TEST_END();
}

int main(void)
{
  METRIC_TEST(test_pe_write_header);

  return METRIC_TEST_END();
}
