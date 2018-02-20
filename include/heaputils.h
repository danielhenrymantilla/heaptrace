#ifndef __MYARENA_H__
#define __MYARENA_H__

#include <stdio.h>
#include <sys/types.h>
#include "mymalloc.h"

#ifndef LIBC_MAINARENA_OFFSET
# if defined(__ARCH__) && __ARCH__ == 64
#  define LIBC_MAINARENA_OFFSET 0xb20
# else
#  define LIBC_MAINARENA_OFFSET 0x780
# endif
#endif

void * mainarena_of_pid (pid_t pid);

void * heaputils_dereference; /* = classic_dereference <static> */

#ifndef DR
# define DR(x) (((uintptr_t (*) (void *)) heaputils_dereference)(x))
#endif

void fprint_arena (FILE * stream, struct malloc_state * arena);

struct malloc_state *
  arena_for_mem (void * mem,
                 struct malloc_state * main_arena,
                 FILE * optional_stream);

void fprint_mem (FILE *, void * mem, struct malloc_state * main_arena);

/* List of "memory handles" to keep track of user pointers to memory blocks
 * \-> SORTED => true_invariant (!next || addr < next->addr)
 */
typedef struct mhandle * mhandle_list;
struct mhandle {
  void *	usr_addr;	/* User's pointer (malloc ret or free arg) */
  size_t	usr_size;	/* Size requested by the user */
  mhandle_list	next;		/* sorted list */
};

void mhandles_add (mhandle_list * mhandles_ptr,
                   void * usr_addr, size_t usr_size);
void mhandles_free (mhandle_list);

void fprint_arena_whole_mem (FILE * stream,
                             struct malloc_state * arena,
                             mhandle_list mhandles);

#endif /* __MYARENA_H__ */