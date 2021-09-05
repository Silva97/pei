#include "tests.h"

#define ASSERT_SET_FIELD(field, name)                     \
  {                                                       \
    char field_name[] = name;                             \
    if (!pe_set_field(pe, field_name, OP_EQUAL, "0x77"))  \
    {                                                     \
      METRIC_TEST_FAIL("Field '" name "' doesn't exist"); \
    }                                                     \
    METRIC_ASSERT(pe64->field == 0x77);                   \
  }

#define ASSERT_SET_STRING_FIELD(field, name)              \
  {                                                       \
    char field_name[] = name;                             \
    if (!pe_set_field(pe, field_name, OP_EQUAL, "abcd"))  \
    {                                                     \
      METRIC_TEST_FAIL("Field '" name "' doesn't exist"); \
    }                                                     \
    METRIC_ASSERT_STRING(pe64->field, "abcd");            \
  }

#define ASSERT_SET_DATA_DIRECTORIES(datadir)                                                           \
  ASSERT_SET_FIELD(optional_header->datadir.virtual_address, "optional." #datadir ".virtual_address"); \
  ASSERT_SET_FIELD(optional_header->datadir.size, "optional." #datadir ".size");

test_t test_set_coff_fields(void)
{
  PE_TEST_INIT();

  ASSERT_SET_FIELD(coff_header->machine, "coff.machine");
  ASSERT_SET_FIELD(coff_header->number_of_sections, "coff.number_of_sections");
  ASSERT_SET_FIELD(coff_header->time_date_stamp, "coff.time_date_stamp");
  ASSERT_SET_FIELD(coff_header->pointer_to_symbol_table, "coff.pointer_to_symbol_table");
  ASSERT_SET_FIELD(coff_header->number_of_symbols, "coff.number_of_symbols");
  ASSERT_SET_FIELD(coff_header->size_of_optional_header, "coff.size_of_optional_header");
  ASSERT_SET_FIELD(coff_header->characteristics, "coff.characteristics");

  PE_TEST_END();
}

test_t test_set_optional_fields(void)
{
  PE_TEST_INIT();

  ASSERT_SET_FIELD(optional_header->magic, "optional.magic");
  ASSERT_SET_FIELD(optional_header->major_linker_version, "optional.major_linker_version");
  ASSERT_SET_FIELD(optional_header->minor_linker_version, "optional.minor_linker_version");
  ASSERT_SET_FIELD(optional_header->size_of_code, "optional.size_of_code");
  ASSERT_SET_FIELD(optional_header->size_of_initialized_data, "optional.size_of_initialized_data");
  ASSERT_SET_FIELD(optional_header->size_of_unitialized_data, "optional.size_of_unitialized_data");
  ASSERT_SET_FIELD(optional_header->entry_point, "optional.entry_point");
  ASSERT_SET_FIELD(optional_header->base_of_code, "optional.base_of_code");
  ASSERT_SET_FIELD(optional_header->image_base, "optional.image_base");
  ASSERT_SET_FIELD(optional_header->section_alignment, "optional.section_alignment");
  ASSERT_SET_FIELD(optional_header->file_alignment, "optional.file_alignment");
  ASSERT_SET_FIELD(optional_header->major_os_version, "optional.major_os_version");
  ASSERT_SET_FIELD(optional_header->minor_os_version, "optional.minor_os_version");
  ASSERT_SET_FIELD(optional_header->major_image_version, "optional.major_image_version");
  ASSERT_SET_FIELD(optional_header->minor_image_version, "optional.minor_image_version");
  ASSERT_SET_FIELD(optional_header->major_subsystem_version, "optional.major_subsystem_version");
  ASSERT_SET_FIELD(optional_header->minor_subsystem_version, "optional.minor_subsystem_version");
  ASSERT_SET_FIELD(optional_header->win32_version_value, "optional.win32_version_value");
  ASSERT_SET_FIELD(optional_header->size_of_image, "optional.size_of_image");
  ASSERT_SET_FIELD(optional_header->size_of_headers, "optional.size_of_headers");
  ASSERT_SET_FIELD(optional_header->checksum, "optional.checksum");
  ASSERT_SET_FIELD(optional_header->subsystem, "optional.subsystem");
  ASSERT_SET_FIELD(optional_header->dll_characteristics, "optional.dll_characteristics");
  ASSERT_SET_FIELD(optional_header->size_of_stack_reserve, "optional.size_of_stack_reserve");
  ASSERT_SET_FIELD(optional_header->size_of_stack_commit, "optional.size_of_stack_commit");
  ASSERT_SET_FIELD(optional_header->size_of_head_reserve, "optional.size_of_head_reserve");
  ASSERT_SET_FIELD(optional_header->size_of_head_commit, "optional.size_of_head_commit");
  ASSERT_SET_FIELD(optional_header->loader_flags, "optional.loader_flags");
  ASSERT_SET_FIELD(optional_header->number_of_rva_and_sizes, "optional.number_of_rva_and_sizes");

  // Data directories
  ASSERT_SET_DATA_DIRECTORIES(export_table);
  ASSERT_SET_DATA_DIRECTORIES(import_table);
  ASSERT_SET_DATA_DIRECTORIES(resource_table);
  ASSERT_SET_DATA_DIRECTORIES(exception_table);
  ASSERT_SET_DATA_DIRECTORIES(certificate_table);
  ASSERT_SET_DATA_DIRECTORIES(base_relocation_table);
  ASSERT_SET_DATA_DIRECTORIES(debug);
  ASSERT_SET_DATA_DIRECTORIES(architecture);
  ASSERT_SET_DATA_DIRECTORIES(global_ptr);
  ASSERT_SET_DATA_DIRECTORIES(tls_table);
  ASSERT_SET_DATA_DIRECTORIES(load_config_table);
  ASSERT_SET_DATA_DIRECTORIES(bound_import);
  ASSERT_SET_DATA_DIRECTORIES(iat);
  ASSERT_SET_DATA_DIRECTORIES(delay_import_descriptor);
  ASSERT_SET_DATA_DIRECTORIES(clr_runtime_header);

  PE_TEST_END();
}

test_t test_set_section_fields(void)
{
  PE_TEST_INIT();

  ASSERT_SET_STRING_FIELD(section_header[2]->name, "section.2.name");
  ASSERT_SET_FIELD(section_header[2]->virtual_size, "section.2.virtual_size");
  ASSERT_SET_FIELD(section_header[2]->virtual_address, "section.2.virtual_address");
  ASSERT_SET_FIELD(section_header[2]->size_of_raw_data, "section.2.size_of_raw_data");
  ASSERT_SET_FIELD(section_header[2]->pointer_to_raw_data, "section.2.pointer_to_raw_data");
  ASSERT_SET_FIELD(section_header[2]->pointer_to_relocations, "section.2.pointer_to_relocations");
  ASSERT_SET_FIELD(section_header[2]->pointer_to_line_numbers, "section.2.pointer_to_line_numbers");
  ASSERT_SET_FIELD(section_header[2]->number_of_relocations, "section.2.number_of_relocations");
  ASSERT_SET_FIELD(section_header[2]->number_of_line_numbers, "section.2.number_of_line_numbers");
  ASSERT_SET_FIELD(section_header[2]->characteristics, "section.2.characteristics");

  PE_TEST_END();
}

int main(void)
{
  METRIC_TEST(test_set_coff_fields);
  METRIC_TEST(test_set_optional_fields);
  METRIC_TEST(test_set_section_fields);

  METRIC_TEST_END();
}
