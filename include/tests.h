#include "win.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "metric.h"
#include "pe.h"
#include "pereader.h"

#define TEST_PE "tests/utils/test.exe"

#define PE_TEST_INIT()                   \
  pe_t *pe = pe_parse(pe_open(TEST_PE)); \
  pe64_t *pe64 __attribute__((unused)) = (pe64_t *)pe

#define PE_TEST_END() \
  pe_free(pe);        \
  METRIC_TEST_OK()
