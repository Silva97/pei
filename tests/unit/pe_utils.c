#include "tests.h"

test_t test_pe_update_entrypoint(void)
{
  PE_TEST_INIT();

  uint32_t entry_point = pe64->optional_header->entry_point;
  METRIC_ASSERT(pe_update_entrypoint(pe, 0x12345) == entry_point);
  METRIC_ASSERT(pe64->optional_header->entry_point == 0x12345);

  PE_TEST_END();
}

test_t test_pe_aslr(void)
{
  PE_TEST_INIT();

  // Make sure dynamic base is enabled
  pe64->optional_header->dll_characteristics |= DYNAMIC_BASE;

  pe_aslr(pe, false);
  METRIC_ASSERT(!(pe64->optional_header->dll_characteristics & DYNAMIC_BASE));

  pe_aslr(pe, true);
  METRIC_ASSERT(pe64->optional_header->dll_characteristics & DYNAMIC_BASE);

  PE_TEST_END();
}

test_t test_pe_offset_to_vaddress(void)
{
  PE_TEST_INIT();
  pe_section_header_t *section = pe64->section_header[0];

  uint32_t offset = section->pointer_to_raw_data + 0x12;
  int64_t expected_vaddress = section->virtual_address + 0x12;
  METRIC_ASSERT(pe_offset_to_vaddress(pe, offset) == expected_vaddress);

  PE_TEST_END();
}

test_t test_pe_image_base(void)
{
  PE_TEST_INIT();

  METRIC_ASSERT(pe64->optional_header->image_base == pe_image_base(pe));

  PE_TEST_END();
}

test_t test_pe_search_address_section(void)
{
  PE_TEST_INIT();
  pe_section_header_t *section = pe64->section_header[3];

  uint32_t address = section->virtual_address + 0x12;
  METRIC_ASSERT(pe_search_address_section(pe, address) == 3);

  PE_TEST_END();
}

test_t test_pe_search_entrypoint_section(void)
{
  PE_TEST_INIT();

  METRIC_ASSERT(pe_search_entrypoint_section(pe) == 0);

  PE_TEST_END();
}

test_t test_pe_search_biggest_zero_sequence(void)
{
  PE_TEST_INIT();

  pe_block_t block = pe_search_biggest_zero_sequence(pe);
  METRIC_ASSERT_STRING(pe64->section_header[block.section]->name, ".data");
  METRIC_ASSERT(block.size == 1012);
  // 1012 is the number of zeros on `dump` variable of test.c

  PE_TEST_END();
}

int main(void)
{
  METRIC_TEST(test_pe_update_entrypoint);
  METRIC_TEST(test_pe_aslr);
  METRIC_TEST(test_pe_offset_to_vaddress);
  METRIC_TEST(test_pe_image_base);
  METRIC_TEST(test_pe_search_address_section);
  METRIC_TEST(test_pe_search_entrypoint_section);
  METRIC_TEST(test_pe_search_biggest_zero_sequence);

  METRIC_TEST_END();
}
