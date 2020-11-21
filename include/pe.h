// Reference:
//   https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
#ifndef PE_H
#define PE_H

#include "win.h"

#include <stdint.h>
#include <stdio.h>
#include <limits.h>

#define PE_SIGNATURE_ADDRESS_OFFSET 0x3c
#define PE_SIGNATURE "PE\0" // {'P', 'E', '\0', '\0'}
#define PE_SIGNATURE_SIZE (sizeof PE_SIGNATURE)
#define SECTION_FIELD_NAME_SIZE 8

typedef struct pe
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  struct pe_coff_header *coff_header;
  void *optional_header;
  struct pe_section_header *section_header[];
} pe_t;

typedef struct pe32
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  struct pe_coff_header *coff_header;
  struct pe32_optional_header *optional_header;
  struct pe_section_header *section_header[];
} pe32_t;

typedef struct pe64
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  struct pe_coff_header *coff_header;
  struct pe64_optional_header *optional_header;
  struct pe_section_header *section_header[];
} pe64_t;

typedef struct pe_data_directory
{
  int32_t virtual_address;
  int32_t size;
} pe_data_directory_t;

typedef struct pe_coff_header
{
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;
  uint16_t characteristics;
} pe_coff_header_t;

#define PE_OPTIONAL_HEADER_STANDARD_FIELDS \
  uint16_t magic;                          \
  uint8_t major_linker_version;            \
  uint8_t minor_linker_version;            \
  uint32_t size_of_code;                   \
  uint32_t size_of_initialized_data;       \
  uint32_t size_of_unitialized_data;       \
  uint32_t entry_point;                    \
  uint32_t base_of_code

#define PE_OPTIONAL_HEADER_WINDOWS_FIELDS(field_type) \
  field_type image_base;                              \
  uint32_t section_alignment;                         \
  uint32_t file_alignment;                            \
  uint16_t major_os_version;                          \
  uint16_t minor_os_version;                          \
  uint16_t major_image_version;                       \
  uint16_t minor_image_version;                       \
  uint16_t major_subsystem_version;                   \
  uint16_t minor_subsystem_version;                   \
  uint32_t win32_version_value;                       \
  uint32_t size_of_image;                             \
  uint32_t size_of_headers;                           \
  uint32_t checksum;                                  \
  uint16_t subsystem;                                 \
  uint16_t dll_characteristics;                       \
  field_type size_of_stack_reserve;                   \
  field_type size_of_stack_commit;                    \
  field_type size_of_head_reserve;                    \
  field_type size_of_head_commit;                     \
  uint32_t loader_flags;                              \
  uint32_t number_of_rva_and_sizes

#define PE_OPTIONAL_HEADER_DATA_DIRECTORIES    \
  pe_data_directory_t export_table;            \
  pe_data_directory_t import_table;            \
  pe_data_directory_t resource_table;          \
  pe_data_directory_t exception_table;         \
  pe_data_directory_t certificate_table;       \
  pe_data_directory_t base_relocation_table;   \
  pe_data_directory_t debug;                   \
  pe_data_directory_t architecture;            \
  pe_data_directory_t global_ptr;              \
  pe_data_directory_t tls_table;               \
  pe_data_directory_t load_config_table;       \
  pe_data_directory_t bound_import;            \
  pe_data_directory_t iat;                     \
  pe_data_directory_t delay_import_descriptor; \
  pe_data_directory_t clr_runtime_header;      \
  pe_data_directory_t reserved

typedef struct pe32_optional_header
{
  PE_OPTIONAL_HEADER_STANDARD_FIELDS;
  int32_t base_of_data;
  PE_OPTIONAL_HEADER_WINDOWS_FIELDS(uint32_t);
  PE_OPTIONAL_HEADER_DATA_DIRECTORIES;
} pe32_optional_header_t;

typedef struct pe64_optional_header
{
  PE_OPTIONAL_HEADER_STANDARD_FIELDS;
  PE_OPTIONAL_HEADER_WINDOWS_FIELDS(uint64_t);
  PE_OPTIONAL_HEADER_DATA_DIRECTORIES;
} pe64_optional_header_t;

typedef struct pe_section_header
{
  char name[SECTION_FIELD_NAME_SIZE];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_line_numbers;
  uint16_t number_of_relocations;
  uint16_t number_of_line_numbers;
  uint32_t characteristics;
} pe_section_header_t;

enum pe_section_flags
{
  TYPE_NO_PAD = 0x00000008,
  CNT_CODE = 0x00000020,
  CNT_INITIALIZED_DATA = 0x00000040,
  CNT_UNINITIALIZED_DATA = 0x00000080,
  LNK_OTHER = 0x00000100,
  LNK_INFO = 0x00000200,
  LNK_REMOVE = 0x00000800,
  LNK_COMDAT = 0x00001000,
  GPREL = 0x00008000,
  MEM_PURGEABLE = 0x00020000,
  MEM_16BIT = 0x00020000,
  MEM_LOCKED = 0x00040000,
  MEM_PRELOAD = 0x00080000,
  ALIGN_1BYTES = 0x00100000,
  ALIGN_2BYTES = 0x00200000,
  ALIGN_4BYTES = 0x00300000,
  ALIGN_8BYTES = 0x00400000,
  ALIGN_16BYTES = 0x00500000,
  ALIGN_32BYTES = 0x00600000,
  ALIGN_64BYTES = 0x00700000,
  ALIGN_128BYTES = 0x00800000,
  ALIGN_256BYTES = 0x00900000,
  ALIGN_512BYTES = 0x00A00000,
  ALIGN_1024BYTES = 0x00B00000,
  ALIGN_2048BYTES = 0x00C00000,
  ALIGN_4096BYTES = 0x00D00000,
  ALIGN_8192BYTES = 0x00E00000,
  LNK_NRELOC_OVFL = 0x01000000,
  MEM_DISCARDABLE = 0x02000000,
  MEM_NOT_CACHED = 0x04000000,
  MEM_NOT_PAGED = 0x08000000,
  MEM_SHARED = 0x10000000,
  MEM_EXECUTE = 0x20000000,
  MEM_READ = 0x40000000,
  MEM_WRITE = INT_MIN, // Workaround to get 0x80000000 value
};

enum pe_machine_type
{
  MACHINE_UNKNOWN = 0x0,
  AM33 = 0x1d3,
  AMD64 = 0x8664,
  ARM = 0x1c0,
  ARM64 = 0xaa64,
  ARMNT = 0x1c4,
  EBC = 0xebc,
  I386 = 0x14c,
  IA64 = 0x200,
  M32R = 0x9041,
  MIPS16 = 0x266,
  MIPSFPU = 0x366,
  MIPSFPU16 = 0x466,
  POWERPC = 0x1f0,
  POWERPCFP = 0x1f1,
  R4000 = 0x166,
  RISCV32 = 0x5032,
  RISCV64 = 0x5064,
  RISCV128 = 0x5128,
  SH3 = 0x1a2,
  SH3DSP = 0x1a3,
  SH4 = 0x1a6,
  SH5 = 0x1a8,
  THUMB = 0x1c2,
  WCEMIPSV2 = 0x169,
};

enum pe32_characteristics
{
  RELOCS_STRIPPED = 0x0001,
  EXECUTABLE_IMAGE = 0x0002,
  LINE_NUMS_STRIPPED = 0x0004,
  LOCAL_SYMS_STRIPPED = 0x0008,
  AGGRESSIVE_WS_TRIM = 0x0010,
  LARGE_ADDRESS_AWARE = 0x0020,
  BYTES_REVERSED_LO = 0x0080,
  BIT32_MACHINE = 0x0100,
  DEBUG_STRIPPED = 0x0200,
  REMOVABLE_RUN_FROM_SWAP = 0x0400,
  NET_RUN_FROM_SWAP = 0x0800,
  SYSTEM = 0x1000,
  UP_SYSTEM_ONLY = 0x4000,
  BYTES_REVERSED_HI = 0x8000,
};

enum pe_magic_number
{
  MAGIC_ROM = 0x107,
  MAGIC_32BIT = 0x10b,
  MAGIC_64BIT = 0x20b,
};

enum pe_subsystem
{
  SUBSYSTEM_UNKNOWN = 0,
  NATIVE = 1,
  WINDOWS_GUI = 2,
  WINDOWS_CUI = 3,
  OS2_CUI = 5,
  POSIX_CUI = 7,
  NATIVE_WINDOWS = 8,
  WINDOWS_CE_GUI = 9,
  EFI_APPLICATION = 10,
  EFI_BOOT_SERVICE_DRIVER = 11,
  EFI_RUNTIME_DRIVER = 12,
  EFI_ROM = 13,
  XBOX = 14,
  WINDOWS_BOOT_APPLICATION = 16,
};

enum pe_dll_characteristic
{
  HIGH_ENTROPY_VA = 0x0020,
  DYNAMIC_BASE = 0x0040,
  FORCE_INTEGRITY = 0x0080,
  NX_COMPAT = 0x0100,
  NO_ISOLATION = 0x0200,
  NO_SEH = 0x0400,
  NO_BIND = 0x0800,
  APPCONTAINER = 0x1000,
  WDM_DRIVER = 0x2000,
  GUARD_CF = 0x4000,
  TERMINAL_SERVER_AWARE = 0x8000,
};

#endif /* PE_H */
