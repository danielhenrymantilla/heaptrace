#include "helpers.h"
#include "myarena.h"
/* from header:
  #ifndef DR
  # define DR(x) (((uintptr_t (*) (void *)) myarena_dereference)(x))
  #endif
*/
#include "mymalloc.h"

#define LINE_SEP "=========================\n"

#ifndef DISABLE_MYPRINTER
# include "myprinter.h"
#else
# define __myfprintf__(...) fprintf(__VA_ARGS__)
# define myfprintf(...) fprintf(__VA_ARGS__)
# if defined(__ARCH__) && __ARCH__ == 64
#  define XT		"0x%lx"
# else
#  define XT		"0x%x"
# endif
# define BT		"0x%02hhx"
#endif

static uintptr_t classic_dereference (void * ptr) {
  return *(uintptr_t *) ptr;
}

void * myarena_dereference = classic_dereference;

#define print(format, ...) \
  myfprintf(stream, format, ##__VA_ARGS__)

static void fprint_chunk(FILE *, void * chunkptr_addr);

static void fprint_bins (FILE *, mchunkptr *, unsigned int * binmap);

static void fprint_fastbins (FILE *, mfastbinptr *);

static void fprint_binmap (FILE *, unsigned int *);

static mchunkptr last_remainder = NULL;

void fprint_arena (FILE * stream, struct malloc_state * arena)
{
  print(LINE_SEP);
  print("Arena at " XT ":\n",
    (uintptr_t) arena);
  last_remainder = (mchunkptr)
    DR(&arena->last_remainder);
  print(" -> (int) flags = " XT "\n",
    DR(&arena->flags));
  print(" -> (int) have_fastchunks = " BT "\n",
    DR(&arena->have_fastchunks));
  print(" -> (mfastbinptr []) fastbinsY (at " XT ") :\n",
    (uintptr_t) &arena->fastbinsY);
  fprint_fastbins(stream, (mfastbinptr *) &arena->fastbinsY);
  print(" -> (mchunkptr) top = " XT "\n",
    DR(&arena->top));
  print(" -> (mchunkptr) last_remainder = " XT "\n",
    (uintptr_t) last_remainder);
  print(" -> (mchunpktr []) bins (at " XT ") :\n",
    (uintptr_t) &arena->bins);
  fprint_bins(stream,
    (mchunkptr *) &arena->bins, (unsigned int *) &arena->binmap);
#ifdef DEBUG
  print(" -> (unsigned int []) binmap (at " XT ") :\n",
    (uintptr_t) &arena->binmap);
  fprint_binmap(stream, (unsigned int *) &arena->binmap);
#endif
  print(" -> (size_t) attached_threads = " BT "\n",
    DR(&arena->attached_threads));
  print(" -> (size_t) system_mem = " XT "\n",
    DR(&arena->system_mem));
  print(" -> (size_t) max_system_mem = " XT "\n",
    DR(&arena->max_system_mem));
  print(LINE_SEP "\n");
}

static void fprint_fastbins (FILE * stream, mfastbinptr * fastbinsY)
{
  for (size_t i = 0; i < NFASTBINS; ++i) {
    mchunkptr * chunk_addr = &fastbinsY[i];
    uintptr_t chunk = DR(chunk_addr);
#ifndef DEBUG
    if (chunk) {
#endif
      print("\t[" BT "] (sz = " BT ") = " XT "    (at " XT ")\n",
        i, 16 + i * 8, chunk, (uintptr_t) chunk_addr);
      fprint_chunk(stream, chunk_addr);
#ifndef DEBUG
    }
#endif
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
      "[ psz:" XT " | "
      "sz:" XT " | "
      "fd:" XT " | "
      "bk:" XT " ]\n",
      DR(&chunk->mchunk_prev_size), DR(&chunk->mchunk_size),
      (uintptr_t) next_chunk, DR(&chunk->bk)
    );
    fprint_chunk_aux(stream, next_chunk, startpoint, tabs + 1);
  }
}

static void fprint_chunk(FILE * stream, void * chunkptr_addr)
{
  mchunkptr startpoint = (mchunkptr)
    (chunkptr_addr - offsetof(struct malloc_chunk, fd));
  fprint_chunk_aux(stream, (mchunkptr) DR(chunkptr_addr), startpoint, 2);
}

static const char * bin_size_of_idx[] = {
#if defined(__ARCH__) && __ARCH__ == 64
  "sz = 0x20", "sz = 0x30", "sz = 0x40", "sz = 0x50", "sz = 0x60", "sz = 0x70",
  "sz = 0x80", "sz = 0x90", "sz = 0xa0", "sz = 0xb0", "sz = 0xc0", "sz = 0xd0",
  "sz = 0xe0", "sz = 0xf0", "sz = 0x100", "sz = 0x110", "sz = 0x120",
  "sz = 0x130", "sz = 0x140", "sz = 0x150", "sz = 0x160", "sz = 0x170",
  "sz = 0x180", "sz = 0x190", "sz = 0x1a0", "sz = 0x1b0", "sz = 0x1c0",
  "sz = 0x1d0", "sz = 0x1e0", "sz = 0x1f0", "sz = 0x200", "sz = 0x210",
  "sz = 0x220", "sz = 0x230", "sz = 0x240", "sz = 0x250", "sz = 0x260",
  "sz = 0x270", "sz = 0x280", "sz = 0x290", "sz = 0x2a0", "sz = 0x2b0",
  "sz = 0x2c0", "sz = 0x2d0", "sz = 0x2e0", "sz = 0x2f0", "sz = 0x300",
  "sz = 0x310", "sz = 0x320", "sz = 0x330", "sz = 0x340", "sz = 0x350",
  "sz = 0x360", "sz = 0x370", "sz = 0x380", "sz = 0x390", "sz = 0x3a0",
  "sz = 0x3b0", "sz = 0x3c0", "sz = 0x3d0", "sz = 0x3e0", "sz = 0x3f0",
  "0x400 <= sz <= 0x438", "0x440 <= sz <= 0x478", "0x480 <= sz <= 0x4b8",
  "0x4c0 <= sz <= 0x4f8", "0x500 <= sz <= 0x538", "0x540 <= sz <= 0x578",
  "0x580 <= sz <= 0x5b8", "0x5c0 <= sz <= 0x5f8", "0x600 <= sz <= 0x638",
  "0x640 <= sz <= 0x678", "0x680 <= sz <= 0x6b8", "0x6c0 <= sz <= 0x6f8",
  "0x700 <= sz <= 0x738", "0x740 <= sz <= 0x778", "0x780 <= sz <= 0x7b8",
  "0x7c0 <= sz <= 0x7f8", "0x800 <= sz <= 0x838", "0x840 <= sz <= 0x878",
  "0x880 <= sz <= 0x8b8", "0x8c0 <= sz <= 0x8f8", "0x900 <= sz <= 0x938",
  "0x940 <= sz <= 0x978", "0x980 <= sz <= 0x9b8", "0x9c0 <= sz <= 0x9f8",
  "0xa00 <= sz <= 0xa38", "0xa40 <= sz <= 0xa78", "0xa80 <= sz <= 0xab8",
  "0xac0 <= sz <= 0xaf8", "0xb00 <= sz <= 0xb38", "0xb40 <= sz <= 0xb78",
  "0xb80 <= sz <= 0xbb8", "0xbc0 <= sz <= 0xbf8", "0xc00 <= sz <= 0xc38",
  "0xc40 <= sz <= 0xdf8", "0xe00 <= sz <= 0xff8", "0x1000 <= sz <= 0x11f8",
  "0x1200 <= sz <= 0x13f8", "0x1400 <= sz <= 0x15f8", "0x1600 <= sz <= 0x17f8",
  "0x1800 <= sz <= 0x19f8", "0x1a00 <= sz <= 0x1bf8", "0x1c00 <= sz <= 0x1df8",
  "0x1e00 <= sz <= 0x1ff8", "0x2000 <= sz <= 0x21f8", "0x2200 <= sz <= 0x23f8",
  "0x2400 <= sz <= 0x25f8", "0x2600 <= sz <= 0x27f8", "0x2800 <= sz <= 0x29f8",
  "0x2a00 <= sz <= 0x2ff8", "0x3000 <= sz <= 0x3ff8", "0x4000 <= sz <= 0x4ff8",
  "0x5000 <= sz <= 0x5ff8", "0x6000 <= sz <= 0x6ff8", "0x7000 <= sz <= 0x7ff8",
  "0x8000 <= sz <= 0x8ff8", "0x9000 <= sz <= 0x9ff8", "0xa000 <= sz <= 0xfff8",
  "0x10000 <= sz <= 0x17ff8", "0x18000 <= sz <= 0x1fff8",
  "0x20000 <= sz <= 0x27ff8", "0x28000 <= sz <= 0x3fff8",
  "0x40000 <= sz <= 0x7fff8", "0x80000 <= sz",
#else
  "sz = 0x10", "sz = 0x18", "sz = 0x20", "sz = 0x28", "sz = 0x30", "sz = 0x38",
  "sz = 0x40", "sz = 0x48", "sz = 0x50", "sz = 0x58", "sz = 0x60", "sz = 0x68",
  "sz = 0x70", "sz = 0x78", "sz = 0x80", "sz = 0x88", "sz = 0x90", "sz = 0x98",
  "sz = 0xa0", "sz = 0xa8", "sz = 0xb0", "sz = 0xb8", "sz = 0xc0", "sz = 0xc8",
  "sz = 0xd0", "sz = 0xd8", "sz = 0xe0", "sz = 0xe8", "sz = 0xf0", "sz = 0xf8",
  "sz = 0x100", "sz = 0x108", "sz = 0x110", "sz = 0x118", "sz = 0x120",
  "sz = 0x128", "sz = 0x130", "sz = 0x138", "sz = 0x140", "sz = 0x148",
  "sz = 0x150", "sz = 0x158", "sz = 0x160", "sz = 0x168", "sz = 0x170",
  "sz = 0x178", "sz = 0x180", "sz = 0x188", "sz = 0x190", "sz = 0x198",
  "sz = 0x1a0", "sz = 0x1a8", "sz = 0x1b0", "sz = 0x1b8", "sz = 0x1c0",
  "sz = 0x1c8", "sz = 0x1d0", "sz = 0x1d8", "sz = 0x1e0", "sz = 0x1e8",
  "sz = 0x1f0", "sz = 0x1f8", "0x200 <= sz <= 0x238", "0x240 <= sz <= 0x278",
  "0x280 <= sz <= 0x2b8", "0x2c0 <= sz <= 0x2f8", "0x300 <= sz <= 0x338",
  "0x340 <= sz <= 0x378", "0x380 <= sz <= 0x3b8", "0x3c0 <= sz <= 0x3f8",
  "0x400 <= sz <= 0x438", "0x440 <= sz <= 0x478", "0x480 <= sz <= 0x4b8",
  "0x4c0 <= sz <= 0x4f8", "0x500 <= sz <= 0x538", "0x540 <= sz <= 0x578",
  "0x580 <= sz <= 0x5b8", "0x5c0 <= sz <= 0x5f8", "0x600 <= sz <= 0x638",
  "0x640 <= sz <= 0x678", "0x680 <= sz <= 0x6b8", "0x6c0 <= sz <= 0x6f8",
  "0x700 <= sz <= 0x738", "0x740 <= sz <= 0x778", "0x780 <= sz <= 0x7b8",
  "0x7c0 <= sz <= 0x7f8", "0x800 <= sz <= 0x838", "0x840 <= sz <= 0x878",
  "0x880 <= sz <= 0x8b8", "0x8c0 <= sz <= 0x8f8", "0x900 <= sz <= 0x938",
  "0x940 <= sz <= 0x978", "0x980 <= sz <= 0x9b8", "0x9c0 <= sz <= 0x9f8",
  "0xa00 <= sz <= 0xbf8", "0xc00 <= sz <= 0xdf8", "0xe00 <= sz <= 0xff8",
  "0x1000 <= sz <= 0x11f8", "0x1200 <= sz <= 0x13f8", "0x1400 <= sz <= 0x15f8",
  "0x1600 <= sz <= 0x17f8", "0x1800 <= sz <= 0x19f8", "0x1a00 <= sz <= 0x1bf8",
  "0x1c00 <= sz <= 0x1df8", "0x1e00 <= sz <= 0x1ff8", "0x2000 <= sz <= 0x21f8",
  "0x2200 <= sz <= 0x23f8", "0x2400 <= sz <= 0x25f8", "0x2600 <= sz <= 0x27f8",
  "0x2800 <= sz <= 0x29f8", "0x2a00 <= sz <= 0x2ff8", "0x3000 <= sz <= 0x3ff8",
  "0x4000 <= sz <= 0x4ff8", "0x5000 <= sz <= 0x5ff8", "0x6000 <= sz <= 0x6ff8",
  "0x7000 <= sz <= 0x7ff8", "0x8000 <= sz <= 0x8ff8", "0x9000 <= sz <= 0x9ff8",
  "0xa000 <= sz <= 0xfff8", "0x10000 <= sz <= 0x17ff8",
  "0x18000 <= sz <= 0x1fff8", "0x20000 <= sz <= 0x27ff8",
  "0x28000 <= sz <= 0x3fff8", "0x40000 <= sz <= 0x7fff8", "0x80000 <= sz"
#endif
};

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1ULL << ((i) & ((1U << BINMAPSHIFT) - 1))))
#define get_binmap(m, i)  (DR(&(m)->binmap[idx2block (i)]) & idx2bit (i))

static void fprint_bins(FILE * stream, mchunkptr * bins, unsigned int * binmap)
{
  print("\t[0x01] (unsorted) = " XT "    (at " XT " + %d)\n",
    DR(bins), (uintptr_t) bins - 2 * SIZE_SZ, 2 * SIZE_SZ);
  fprint_chunk(stream, bins);
  for (size_t i = 2; i < NBINS; ++i) {
    if ((uintptr_t) DR(&binmap[idx2block (i)]) & idx2bit (i)) {
      mchunkptr * chunk_addr = &bins[2 * (i - 1)];
      print("\t[" BT "] (", i);
      print(bin_size_of_idx[i - 2]);
      print(") = " XT "    (at " XT " + %d)\n",
        DR(chunk_addr), (uintptr_t) chunk_addr - 2 * SIZE_SZ, 2 * SIZE_SZ);
      fprint_chunk(stream, chunk_addr);
    }
  }
}

static void fprint_binmap (FILE * stream, unsigned int * binmap)
{
  for (size_t i = 1; i < NBINS; ++i) {
    print((uintptr_t) DR(&binmap[idx2block (i)]) & idx2bit (i) ? "1" : "0");
    if (i % BITSPERMAP == 0)
      print(" ");
  }
  print("\n");
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

void fprint_mem (FILE * stream,
                 void * mem,
                 struct malloc_state * main_arena)
{
  mchunkptr chunk = mem2chunk(mem);
  print(LINE_SEP "Got chunk at " XT " (from mem = " XT "):\n",
    (uintptr_t) chunk, (uintptr_t) mem);
  mchunkptr nextchunk = (mchunkptr) DR(&chunk->fd);
  fprint_chunk_aux(stream, chunk, nextchunk, 1);
  print(LINE_SEP "\n");
  fprint_arena(stream, arena_for_mem(mem, main_arena, stream));
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

#define chunk_non_main_arena(p) (DR(&((p)->mchunk_size)) & NON_MAIN_ARENA)

#define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))

struct malloc_state *
  arena_for_mem (void * mem, struct malloc_state * main_arena, FILE * stream)
{
  mchunkptr chunk = mem2chunk(mem);
  if chunk_non_main_arena(chunk) {
    heap_info * heap = heap_for_ptr(chunk);
    printd_var(heap);
    struct malloc_state *
      arena = (struct malloc_state *) DR(&heap->ar_ptr);
    if (stream)
      print(BANNER "Chunk at " XT " does not use the main_arena at " XT " "
        "but uses its own arena at " XT " (read from " XT ")\n",
            (uintptr_t) chunk, (uintptr_t) main_arena,
            (uintptr_t) arena, (uintptr_t) &heap->ar_ptr);
    return arena;
  }
  return main_arena;
}

static void * arena_start_mem (struct malloc_state * arena)
{
  mchunkptr top_chunk = (mchunkptr) DR(&arena->top);
  if (!top_chunk) return NULL;
  size_t top_chunk_size = DR(&top_chunk->mchunk_size);
  if (!top_chunk_size) return NULL;
  uintptr_t last_addr = (uintptr_t) top_chunk + top_chunk_size;
  uintptr_t first_addr = last_addr - DR(&arena->system_mem);
  return (void *) (first_addr & ~MALLOC_ALIGN_MASK);
}

void fprint_arena_whole_mem (FILE * stream,
                             struct malloc_state * arena,
                             mhandle_list mhandles)
{
  void * start = arena_start_mem(arena);
  if (!start) return;
  printd_var(start);
  void * end = (void *) DR(&arena->top) + 24; // DR(&arena->system_mem);
  printd_var(end);
  print(LINE_SEP);
  size_t remaining_inuse_sz = 0;
  for (void * ptr = start; ptr < end; ptr += sizeof(long)) {
    while (mhandles && mhandles->usr_addr < ptr) mhandles = mhandles->next;
    if (mhandles && mhandles->usr_addr == ptr) {
      remaining_inuse_sz = mhandles->usr_size;
      print("--> ");
    } else
      print("    ");
    uintptr_t value = DR(ptr);
    if (remaining_inuse_sz) print("\e[33m|");
    else print(" ");
    print(XT ": " XT "\n", (uintptr_t) ptr, value);
    if (remaining_inuse_sz) print("\e[m");
    remaining_inuse_sz = remaining_inuse_sz < sizeof(long) ?
      0 :
      remaining_inuse_sz - sizeof(long);
  }
  print(LINE_SEP "\n");
}

void mhandles_add (mhandle_list * mhandles_ptr,
                   void * usr_addr, size_t usr_size)
{
  if (!mhandles_ptr) print_fail("mhandles_add: got NULL");
  printd_var(usr_addr);
  printd_var(usr_size);
  if (!(*mhandles_ptr) || usr_addr < (*mhandles_ptr)->usr_addr) {
    mhandle_list next = *mhandles_ptr;
    *mhandles_ptr = malloc(sizeof(**mhandles_ptr));
    if (!(*mhandles_ptr)) failwith("mhandles_add: couldn't malloc");
    (*mhandles_ptr)->usr_addr = usr_addr;
    (*mhandles_ptr)->usr_size = usr_size;
    (*mhandles_ptr)->next = next;
  } else if ((*mhandles_ptr)->usr_addr == usr_addr) {
    (*mhandles_ptr)->usr_size = usr_size;
  } else /* ((*mhandles_ptr)->usr_addr < usr_addr) */ {
    mhandles_add(&(*mhandles_ptr)->next, usr_addr, usr_size);
  }
}

void mhandles_free (mhandle_list mhandles)
{
  if (mhandles) {
    mhandles_free(mhandles->next);
    free(mhandles);
  }
}
