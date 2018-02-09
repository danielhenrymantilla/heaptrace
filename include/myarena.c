#include "helpers.h"
#include "myarena.h"
/* from header:
  #ifndef DR
  #define DR(x) (((void * (*) (void *)) myarena_dereference)(x))
  #endif
*/
#include "mymalloc.h"

#define DISABLE_MYPRINTER
#ifndef DISABLE_MYPRINTER
 #include "myprinter.h"
#else
 #define __myfprintf__(...) fprintf(__VA_ARGS__)
 #define myfprintf(...) fprintf(__VA_ARGS__)
 #if defined(__ARCH__) && __ARCH__ == 64
  #define XT		"0x%lx"
 #else
  #define XT		"0x%x"
 #endif
 #define BT		"0x%hhx"
#endif

static uintptr_t classic_dereference (void * ptr) {
  return *(uintptr_t *) ptr;
}

void * myarena_dereference = classic_dereference;

/* FLD_AT(struct, field) == (void *) (&struct->field) */
#define FLD_AT(structure_ptr, field_name)		\
  (							\
    (void *) (structure_ptr) +				\
    offsetof(						\
      typeof( *(structure_ptr) ),			\
      field_name)					\
  )

/* FLD(struct, field) == (void *) (struct->field) // using DR */
#define FLD(structure_ptr, field_name) \
  (DR(FLD_AT(structure_ptr, field_name)))

#define print(format, ...) \
  myfprintf(stream, format, ##__VA_ARGS__)
//  myfprintf(stream, "\e[33m" format "\e[m", ##__VA_ARGS__)

static void fprint_chunk(FILE *, void * chunkptr_addr);

static void fprint_bins (FILE *, mchunkptr *, unsigned int *);

static void fprint_fastbins (FILE *, mfastbinptr *);

static mchunkptr last_remainder = NULL;

void fprint_arena (FILE * stream, struct malloc_state * arena)
{
  print("=========================\n");
  print("Arena at " XT ":\n", (uintptr_t) arena);
  print("\\-> flags = " XT ",", DR(&arena->flags));
  print(" have_fastchunks = " BT ",", DR(&arena->have_fastchunks));
  print(" attached_threads = " BT ",", DR(&arena->attached_threads));
  print(" system_mem = " XT ",", DR(&arena->system_mem));
  print(" max_system_mem = " XT "\n", DR(&arena->max_system_mem));
  print(" -> top = " XT "\n", DR(&arena->top));
  last_remainder = (mchunkptr) DR(&arena->last_remainder);
  print(" -> last_remainder = " XT "\n", (uintptr_t) last_remainder);
  print(" -> fastbinsY (at " XT ") :\n", (uintptr_t) &arena->fastbinsY);
  fprint_fastbins(stream, (mfastbinptr *) &arena->fastbinsY);
  print(" -> bins (at " XT ") :\n", (uintptr_t) &arena->bins);
  fprint_bins(
    stream, (mchunkptr *) &arena->bins, (unsigned int *) &arena->binmap);
  print("=========================\n\n");
}

static void fprint_fastbins (FILE * stream, mfastbinptr * fastbinsY)
{
  for (size_t i = 0; i < NFASTBINS; ++i) {
    mchunkptr * chunk_addr = &fastbinsY[i];
    print("\t[" BT "] = " XT "\n", i, DR(chunk_addr));
    fprint_chunk(stream, chunk_addr);
  }
}

static void fprint_chunk_aux(FILE * stream,
                             mchunkptr chunk,
                             mchunkptr startpoint,
                             size_t tabs)
{
  if (chunk && chunk != startpoint) {
    for (size_t i = 0; i < tabs; ++i) print("\t");
    if (chunk == last_remainder)
      print("<LR> ");
    mchunkptr next_chunk = (mchunkptr) DR(&chunk->fd);
    print("\\-> "
      "[ prev_sz: " XT " | "
      "sz: " XT " | "
      "fd: " XT " | "
      "bk: " XT " ]\n",
      DR(&chunk->mchunk_prev_size), DR(&chunk->mchunk_size),
      (uintptr_t) next_chunk, DR(&chunk->bk)
    );
    fprint_chunk_aux(stream, next_chunk, startpoint, tabs + 1);
  }
}

static void fprint_chunk(FILE * stream, void * chunkptr_addr)
{
  mchunkptr startpoint =
    (mchunkptr) (chunkptr_addr - offsetof(struct malloc_chunk, fd));
  fprint_chunk_aux(stream, (mchunkptr) DR(chunkptr_addr), startpoint, 2);
}

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1ULL << ((i) & ((1U << BINMAPSHIFT) - 1))))
#define get_binmap(m, i)  (DR(&(m)->binmap[idx2block (i)]) & idx2bit (i))

static void fprint_bins(FILE * stream, mchunkptr * bins, unsigned int * binmap)
{
  print("\t[0x01] (a.k.a \"unsorted\") = " XT "\n", DR(bins));
  fprint_chunk(stream, bins);
  for (size_t i = 2; i < NBINS; ++i) {
    if ((uintptr_t) DR(&binmap[idx2block (i)]) & idx2bit (i)) {
      mchunkptr * chunk_addr = &bins[2 * (i - 1)];
      print("\t[" BT "] = " XT "\n", i, DR(chunk_addr));
      fprint_chunk(stream, chunk_addr);
    }
  }
}

/* With /proc/$pid/maps to get access to the virtual memory mapping (vmmap),
 * the writable page from the libc is located,
 * and with the right offset we get the address of the main arena */
void * mainarena_of_pid (pid_t pid)
{
#if defined(__ARCH__) && __ARCH__ == 64
 #define LIBC "/lib/x86_64-linux-gnu/libc-2.23.so"
#else
 #define LIBC "/lib/i386-linux-gnu/libc-2.23.so"
#endif
#ifdef DISABLE_MYPRINTER
  char * vmmap_filename = NULL;
  asprintf(&vmmap_filename, "/proc/%hu/maps", pid);
#else
  char vmmap_filename[16 + 1] = "/proc/"; /* "/proc/...../maps" */
  {
    char s_pid[5 + 1];
    size_t i = 5 + 1;
    s_pid[--i] = '\0';
    int n = pid & 0xffff;
    while (n) {
      s_pid[--i] = (n % 10) + '0';
      n /= 10;
    }
    strcat(vmmap_filename, &s_pid[i]);
  }
  strcat(vmmap_filename, "/maps");
#endif
  printd_low("cat %s\n", vmmap_filename);
  FILE * vmmap = fopen(vmmap_filename, "r");
  if (!vmmap)
    failwith("fopen");
  char * line = NULL;
  size_t n = 0;
  while (getline(&line, &n, vmmap) != -1) {
    printd_low("%s\n", line);
    if (strstr(line, " rw-p ")		/* writable page */
      && strstr(line, " " LIBC)) {	/* at libc */
        printd("Good line: %s\n", line);
        long long ret = strtoll(line, NULL, 0x10);
        printd("Parsed '0x%llx'\n", ret);
        free(line);
        fclose(vmmap);
        return (void *)((uintptr_t)ret + LIBC_MAINARENA_OFFSET);
    }
    free(line);
    line = NULL;
    n = 0;
  }
  free(line);
  fclose(vmmap);
  printd("Failed to locate writable libc page.\n");
  return NULL;
}

void fprint_mem_chunk (FILE * stream,
                       void * mem,
                       struct malloc_state * main_arena)
{
  mchunkptr chunk = (mchunkptr) (mem - offsetof(struct malloc_chunk, fd));
  print("Got chunk at " XT " (from mem = " XT "):\n", (void *) chunk, mem);
  print("\-> prev_size = " XT "\n"
        "\-> size = " XT "\n"
        "\-> fd = " XT "\n"
        "\-> bk = " XT "\n",
        DR(&chunk->mchunk_prev_size),
        DR(&chunk->mchunk_size),
        DR(&chunk->fd),
        DR(&chunk->bk));
  // arena_for_mem(mem, main_arena);
}

typedef struct _heap_info
{
  struct malloc_state * ar_ptr; /* Arena for this heap. */
  struct _heap_info * prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;

#define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))

struct malloc_state *
  arena_for_mem (void * mem, struct malloc_state * main_arena)
{
  mchunkptr chunk = mem2chunk(mem);
  if (!chunk_main_arena(chunk)) {
    heap_info * heap = heap_for_ptr(chunk);
    printd_var(heap);
    struct malloc_state * arena = (struct malloc_state *) DR(&heap->ar_ptr);
    printd("Chunk at " XT " does not use main_arena (at " XT ") but uses:\n"
           "-> its own heap at " XT "\n"
           "-> its own arena at " XT " (read at " XT ")\n",
           (uintptr_t) chunk, (uintptr_t) main_arena,
           (uintptr_t) heap,
           (uintptr_t) arena, (uintptr_t) heap + offsetof(heap_info, ar_ptr));
    return arena;
  }
  return main_arena;
}
