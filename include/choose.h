#ifndef _CHOOSE_H
#define _CHOOSE_H

#define CHOICE(value) \
  value, #value

#define FINAL(value) \
  CHOICE(value), 0, NULL

char *choose(int value, ...);

#endif /* _CHOOSE_H */
