#ifndef __ELFUTILS_H__
#define __ELFUTILS_H__
#include <stdlib.h>
#include <stdint.h>

int open_raw_binary (const char * binaryname, const char ** raw_binary_addr);

int close_raw_binary (int fd, const char * raw_binary);

void lookup_symbols (uintptr_t * addresses,
                     const char * raw_binary,
                     const char ** symbols,
                     size_t n);

uintptr_t lookup_symbol (const char * raw_binary, const char * symbol);

#endif /* __ELFUTILS_H__ */
