#ifndef _OPERATIONS_H
#define _OPERATIONS_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "pe.h"
#include "pereader.h"

void op_show(pe_t *pe, char *info, int section, bool verbose);
void op_get(pe_t *pe, char *field_string, const char *format);
void op_edit(pe_t *pe, char *field_string, char *operator, char * value);
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

// Mask to print offset
#define PRIoff "0x%016" PRIx64

#define PRINT_BLOCK(pe, block)                                             \
    printf("Section #%" PRId16 " '%s': " PRIoff " of %" PRId64 " bytes\n", \
           block.section,                                                  \
           pe->section_header[block.section]->name,                        \
           block.offset,                                                   \
           block.size)

#define BLOCK_MIN_SIZE 4

#endif /* _OPERATIONS_H */
