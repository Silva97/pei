#include <tests.h>
#include "choose.h"

enum
{
  TEST_CHOOSE_ONE = 1,
  TEST_CHOOSE_TWO = 2,
  TEST_CHOOSE_THREE = 3,
};

test_t test_choose(void)
{
  char *expected[] = {
      [TEST_CHOOSE_ONE] = "TEST_CHOOSE_ONE",
      [TEST_CHOOSE_TWO] = "TEST_CHOOSE_TWO",
      [TEST_CHOOSE_THREE] = "TEST_CHOOSE_THREE",
  };

  for (int i = 1; i < 4; i++)
  {
    char *result = choose(i,
                          CHOICE(TEST_CHOOSE_ONE),
                          CHOICE(TEST_CHOOSE_TWO),
                          FINAL(TEST_CHOOSE_THREE));

    METRIC_ASSERT(result == expected[i]);
  }

  METRIC_TEST_OK();
}

int main(void)
{
  METRIC_TEST(test_choose);

  METRIC_TEST_END();
}
