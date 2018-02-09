#ifndef __MYMALLOC_H__
#define __MYMALLOC_H__

#include <malloc.h>

#define INTERNAL_SIZE_T size_t

#define SIZE_SZ (sizeof (INTERNAL_SIZE_T)) /* 4 */

#define MALLOC_ALIGNMENT (2 * SIZE_SZ) /* 8 */

#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1) /* 0b111 */

#define chunk2mem(p)   ((void *)((char *)(p) + 2 * SIZE_SZ)) /* +8 */
#define mem2chunk(mem) ((mchunkptr)((char *)(mem) - 2 * SIZE_SZ)) /* -8 */

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE  (offsetof(struct malloc_chunk, fd_nextsize)) /* 16 */

#define MINSIZE (unsigned long) \
  (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)) /* 16 */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk * fd;         /* double links -- used only if free. */
  struct malloc_chunk * bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk * mchunkptr;

#define NBINS             128
#define NSMALLBINS         64

#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2) /* (x >> 3) - 2 */

/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4) /* 80 bytes */

#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1) /* 10 */
typedef struct malloc_chunk *mfastbinptr;

struct malloc_state
{
  int flags; /* Flags (formerly in max_fast).  */
  int have_fastchunks; /* Do fastbin chunks contain recent free blocks? */
  mfastbinptr fastbinsY[NFASTBINS]; /* 10 fastbins */
  mchunkptr top; /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr last_remainder;/* from the most recent split of a small request */
  mchunkptr bins[NBINS * 2 - 2]; /* 254 normal bins */
  unsigned int binmap[BINMAPSIZE]; /* Bitmap of bins (size = 4 unsigned) */
  struct malloc_state * next; /* Linked list */
  struct malloc_state * next_free; /* Linked list for free arenas. */
  INTERNAL_SIZE_T attached_threads; /* to this arena. 0 if on free list */
  INTERNAL_SIZE_T system_mem; /* Memory from the system in this arena.  */
  INTERNAL_SIZE_T max_system_mem;
};

#endif /* __MALLOC_H__ */
