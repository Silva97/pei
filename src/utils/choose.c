#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "choose.h"

char *choose(int value, ...)
{
  va_list ap;
  va_start(ap, value);

  while (true)
  {
    int choice = va_arg(ap, int);
    char *choice_name = va_arg(ap, char *);
    if (!choice_name)
    {
      break;
    }

    if (value == choice)
    {
      va_end(ap);
      return choice_name;
    }
  }

  va_end(ap);
  return NULL;
}
