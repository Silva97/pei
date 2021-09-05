#include "tests.h"

#define ASSERT_FIELD(field, name)                         \
  {                                                       \
    char buff[32];                                        \
    char field_name[] = name;                             \
    int64_t number = 0;                                   \
    if (!pe_get_field(pe, buff, field_name, "%d"))        \
    {                                                     \
      METRIC_TEST_FAIL("Field '" name "' doesn't exist"); \
    }                                                     \
    sscanf(buff, "%" SCNd64, &number);                    \
    METRIC_ASSERT(pe64->field == number);                 \
  }

#define ASSERT_STRING_FIELD(field, name)                  \
  {                                                       \
    char buff[32];                                        \
    char field_name[] = name;                             \
    if (!pe_get_field(pe, buff, field_name, "%s"))        \
    {                                                     \
      METRIC_TEST_FAIL("Field '" name "' doesn't exist"); \
    }                                                     \
    METRIC_ASSERT_STRING(pe64->field, buff);              \
  }

#define ASSERT_DATA_DIRECTORY(datadir)                                                             \
  ASSERT_FIELD(optional_header->datadir.virtual_address, "optional." #datadir ".virtual_address"); \
  ASSERT_FIELD(optional_header->datadir.size, "optional." #datadir ".size")

test_t test_try_get_inexistent_field_expects_false(void)
{
  PE_TEST_INIT();
  char buff[32];
  char field[] = "coff.wrong";

  METRIC_ASSERT(!pe_get_field(pe, buff, field, "%d"));

  PE_TEST_END();
}

test_t test_get_coff_fields(void)
{
  PE_TEST_INIT();

  ASSERT_FIELD(coff_header->machine, "coff.machine");
  ASSERT_FIELD(coff_header->number_of_sections, "coff.number_of_sections");
  ASSERT_FIELD(coff_header->time_date_stamp, "coff.time_date_stamp");
  ASSERT_FIELD(coff_header->pointer_to_symbol_table, "coff.pointer_to_symbol_table");
  ASSERT_FIELD(coff_header->number_of_symbols, "coff.number_of_symbols");
  ASSERT_FIELD(coff_header->size_of_optional_header, "coff.size_of_optional_header");
  ASSERT_FIELD(coff_header->characteristics, "coff.characteristics");

  PE_TEST_END();
}

test_t test_get_optional_fields(void)
{
  PE_TEST_INIT();

  ASSERT_FIELD(optional_header->magic, "optional.magic");
  ASSERT_FIELD(optional_header->major_linker_version, "optional.major_linker_version");
  ASSERT_FIELD(optional_header->minor_linker_version, "optional.minor_linker_version");
  ASSERT_FIELD(optional_header->size_of_code, "optional.size_of_code");
  ASSERT_FIELD(optional_header->size_of_initialized_data, "optional.size_of_initialized_data");
  ASSERT_FIELD(optional_header->size_of_unitialized_data, "optional.size_of_unitialized_data");
  ASSERT_FIELD(optional_header->entry_point, "optional.entry_point");
  ASSERT_FIELD(optional_header->base_of_code, "optional.base_of_code");
  ASSERT_FIELD(optional_header->image_base, "optional.image_base");
  ASSERT_FIELD(optional_header->section_alignment, "optional.section_alignment");
  ASSERT_FIELD(optional_header->file_alignment, "optional.file_alignment");
  ASSERT_FIELD(optional_header->major_os_version, "optional.major_os_version");
  ASSERT_FIELD(optional_header->minor_os_version, "optional.minor_os_version");
  ASSERT_FIELD(optional_header->major_image_version, "optional.major_image_version");
  ASSERT_FIELD(optional_header->minor_image_version, "optional.minor_image_version");
  ASSERT_FIELD(optional_header->major_subsystem_version, "optional.major_subsystem_version");
  ASSERT_FIELD(optional_header->minor_subsystem_version, "optional.minor_subsystem_version");
  ASSERT_FIELD(optional_header->win32_version_value, "optional.win32_version_value");
  ASSERT_FIELD(optional_header->size_of_image, "optional.size_of_image");
  ASSERT_FIELD(optional_header->size_of_headers, "optional.size_of_headers");
  ASSERT_FIELD(optional_header->checksum, "optional.checksum");
  ASSERT_FIELD(optional_header->subsystem, "optional.subsystem");
  ASSERT_FIELD(optional_header->dll_characteristics, "optional.dll_characteristics");
  ASSERT_FIELD(optional_header->size_of_stack_reserve, "optional.size_of_stack_reserve");
  ASSERT_FIELD(optional_header->size_of_stack_commit, "optional.size_of_stack_commit");
  ASSERT_FIELD(optional_header->size_of_head_reserve, "optional.size_of_head_reserve");
  ASSERT_FIELD(optional_header->size_of_head_commit, "optional.size_of_head_commit");
  ASSERT_FIELD(optional_header->loader_flags, "optional.loader_flags");
  ASSERT_FIELD(optional_header->number_of_rva_and_sizes, "optional.number_of_rva_and_sizes");

  // Data directories
  ASSERT_DATA_DIRECTORY(export_table);
  ASSERT_DATA_DIRECTORY(import_table);
  ASSERT_DATA_DIRECTORY(resource_table);
  ASSERT_DATA_DIRECTORY(exception_table);
  ASSERT_DATA_DIRECTORY(certificate_table);
  ASSERT_DATA_DIRECTORY(base_relocation_table);
  ASSERT_DATA_DIRECTORY(debug);
  ASSERT_DATA_DIRECTORY(architecture);
  ASSERT_DATA_DIRECTORY(global_ptr);
  ASSERT_DATA_DIRECTORY(tls_table);
  ASSERT_DATA_DIRECTORY(load_config_table);
  ASSERT_DATA_DIRECTORY(bound_import);
  ASSERT_DATA_DIRECTORY(iat);
  ASSERT_DATA_DIRECTORY(delay_import_descriptor);
  ASSERT_DATA_DIRECTORY(clr_runtime_header);

  PE_TEST_END();
}

test_t test_get_section_fields(void)
{
  PE_TEST_INIT();

  ASSERT_STRING_FIELD(section_header[2]->name, "section.2.name");
  ASSERT_FIELD(section_header[2]->virtual_size, "section.2.virtual_size");
  ASSERT_FIELD(section_header[2]->virtual_address, "section.2.virtual_address");
  ASSERT_FIELD(section_header[2]->size_of_raw_data, "section.2.size_of_raw_data");
  ASSERT_FIELD(section_header[2]->pointer_to_raw_data, "section.2.pointer_to_raw_data");
  ASSERT_FIELD(section_header[2]->pointer_to_relocations, "section.2.pointer_to_relocations");
  ASSERT_FIELD(section_header[2]->pointer_to_line_numbers, "section.2.pointer_to_line_numbers");
  ASSERT_FIELD(section_header[2]->number_of_relocations, "section.2.number_of_relocations");
  ASSERT_FIELD(section_header[2]->number_of_line_numbers, "section.2.number_of_line_numbers");
  ASSERT_FIELD(section_header[2]->characteristics, "section.2.characteristics");

  PE_TEST_END();
}

int main(void)
{
  METRIC_TEST(test_try_get_inexistent_field_expects_false);
  METRIC_TEST(test_get_coff_fields);
  METRIC_TEST(test_get_optional_fields);
  METRIC_TEST(test_get_section_fields);

  METRIC_TEST_END();
}
