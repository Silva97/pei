#ifndef _CHOICE_H
#define _CHOICE_H

#define CHOICE(value) \
  value, #value

#define FINAL(value) \
  CHOICE(value), 0, NULL

char *choose(int value, ...);

#endif /* _CHOICE_H */
