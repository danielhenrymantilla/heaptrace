#ifndef __MYARENA_H__
#define __MYARENA_H__

#include <stdio.h>
#include <sys/types.h>
#include "mymalloc.h"

#ifndef LIBC_MAINARENA_OFFSET
 #if defined(__ARCH__) && __ARCH__ == 64
  #define LIBC_MAINARENA_OFFSET 0xb20
 #else
  #define LIBC_MAINARENA_OFFSET 0x780
 #endif
#endif

void * mainarena_of_pid (pid_t pid);

void * myarena_dereference;

void fprint_arena (FILE * stream, struct malloc_state * arena);

void fprint_mem_chunk (FILE *, void * mem, struct malloc_state *);

#ifndef DR
 #define DR(x) (((uintptr_t (*) (void *)) myarena_dereference)(x))
#endif

#endif /* __MYARENA_H__ */
