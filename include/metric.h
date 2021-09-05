/**
 * Developed by Luiz Felipe <felipe.silva337@yahoo.com>
 * GitHub: https://github.com/Silva97/metric
 *
 *
 * MIT License
 *
 * Copyright (c) 2020 Luiz Felipe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _METRIC_H
#define _METRIC_H

#include <stdio.h>
#include <string.h>
#include <time.h>

typedef const char *test_t;

/* Variables */
static int metric_count_tests_fail = 0;
static int metric_count_tests_ok = 0;

#ifdef NDEBUG

#define METRIC_DISPLAY(name, start, stop)
#define METRIC_START()
#define METRIC_STOP(name)
#define METRIC_CALL(times, call, ...)
#define METRIC_LOG(mask, ...)
#define METRIC_LOG_ARRAY(mask, array, length)
#define METRIC_TEST_OK(msg)
#define METRIC_TEST_FAIL(msg)
#define METRIC_TEST(test)
#define METRIC_TEST_END()
#define METRIC_ASSERT(expr)
#define METRIC_ASSERT_ARRAY(arr1, arr2, size)
#define METRIC_ASSERT_STRING(str1, str2)

#else

#ifdef ANSI_COLORS

#define AC_R "\x1b[31;1m"
#define AC_G "\x1b[32;1m"
#define AC_Y "\x1b[33;1m"
#define AC_B "\x1b[34;1m"
#define AC_W "\x1b[37;1m"
#define AC_N "\x1b[0m"

#else

#define AC_R
#define AC_G
#define AC_Y
#define AC_B
#define AC_W
#define AC_N

#endif /* ANSI_COLORS */

#define METRIC_DISPLAY(name, start, stop)                             \
  printf("<" AC_Y "BENCH" AC_N "> " __FILE__ ": " AC_W name AC_N "\n" \
         "        %lld clocks, %.8lf secs\n",                         \
         (long long int)(stop - start),                               \
         ((double)stop - start) / CLOCKS_PER_SEC)

#define METRIC_START() \
  {                    \
    clock_t metric_clock_start = clock()

#define METRIC_STOP(name)                            \
  METRIC_DISPLAY(name, metric_clock_start, clock()); \
  }

#define METRIC_CALL(times, call, ...)                                                                                       \
  {                                                                                                                         \
    volatile clock_t metric_clock_min_start = 0;                                                                            \
    volatile clock_t metric_clock_min_end;                                                                                  \
    volatile clock_t metric_clock_start;                                                                                    \
    volatile clock_t metric_clock_end;                                                                                      \
    int metric_count;                                                                                                       \
    for (metric_count = 0; metric_count < times; metric_count++)                                                            \
    {                                                                                                                       \
      metric_clock_start = clock();                                                                                         \
      call(__VA_ARGS__);                                                                                                    \
      metric_clock_end = clock();                                                                                           \
      if (!metric_clock_min_start || metric_clock_end - metric_clock_start < metric_clock_min_end - metric_clock_min_start) \
      {                                                                                                                     \
        metric_clock_min_start = metric_clock_start;                                                                        \
        metric_clock_min_end = metric_clock_end;                                                                            \
      }                                                                                                                     \
    }                                                                                                                       \
    METRIC_DISPLAY(#call "(" #__VA_ARGS__ ") x " #times,                                                                    \
                   metric_clock_min_start, metric_clock_min_end);                                                           \
  }

/*** Utils ***/

#define METRIC_LOG(mask, ...) \
  printf("<" AC_W "LOG" AC_N "> " mask, __VA_ARGS__)

#define METRIC_LOG_ARRAY(mask, array, length)               \
  {                                                         \
    printf("<" AC_W "LOG" AC_N "> " #array "[%d] = {" mask, \
           (int)(length), array[0]);                        \
    for (int i = 1; i < length; i++)                        \
      printf(", " mask, array[i]);                          \
    puts("}");                                              \
  }

/*** Unit test macros ***/

#define METRIC_TEST_OK(msg)               \
  {                                       \
    metric_count_tests_ok++;              \
    return "[" AC_G " OK " AC_N "] " msg; \
  }

#define METRIC_TEST_FAIL(msg)             \
  {                                       \
    metric_count_tests_fail++;            \
    return "[" AC_R "FAIL" AC_N "] " msg; \
  }

#define METRIC_TEST(test)                                                     \
  printf("<" AC_B "TEST" AC_N "> " __FILE__ ":%d: " AC_W #test AC_N "\n%s\n", \
         __LINE__,                                                            \
         test())

#define METRIC_TEST_END()                                 \
  printf("\nTests: %d | Failures: " AC_R "%d" AC_N        \
         " | Successes: " AC_G "%d" AC_N "\n\n",          \
         metric_count_tests_fail + metric_count_tests_ok, \
         metric_count_tests_fail,                         \
         metric_count_tests_ok);                          \
  return metric_count_tests_fail

#define METRIC_ASSERT(expr) \
  if (!(expr))              \
  METRIC_TEST_FAIL("The assertion is false: `" #expr "'")

#define METRIC_ASSERT_ARRAY(arr1, arr2, size) \
  if (memcmp(arr1, arr2, size))               \
  METRIC_TEST_FAIL("Array `" #arr1 "' is not equal to `" #arr2 "'")

#define METRIC_ASSERT_STRING(str1, str2) \
  if (strcmp(str1, str2))                \
  METRIC_TEST_FAIL("String `" #str1 "' is not equal to `" #str2 "'")

#endif /* NDEBUG */

#endif /* _METRIC_H */
