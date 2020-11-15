#ifndef _OPERATIONS_H
#define _OPERATIONS_H

#include <stdbool.h>
#include "pe.h"

void op_show(pe_t *pe, char *info, int section, bool verbose);
void op_zeros(pe_t *pe, int section);
void op_inject(pe_t *pe, char *filename, int section);
void op_flags(pe_t *pe, char *flags, int section);

#define FLAG_SET(flags, flagbit, enable) \
    {                                    \
        if (enable)                      \
        {                                \
            flags |= flagbit;            \
        }                                \
        else                             \
        {                                \
            flags &= ~flagbit;           \
        }                                \
    }

#endif /* _OPERATIONS_H */
