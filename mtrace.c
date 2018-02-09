#include "mtrace.h"

extern void * myarena_dereference;

static void usage (const char * progname)
{
  fprintf(stderr, "Usage: %s command [arg ...]\n", progname);
  exit(EXIT_FAILURE);
}

static tracee_t * tracee;

static long tracee_deref (void * ptr)
{
  printd_low(BANNER "tracee_deref: *(%p) = ", ptr);
  long ret = ptrace(PTRACE_PEEKDATA, tracee->pid, ptr, NULL);
  if (ret == -1) failwith("tracee_deref: PTRACE_PEEKDATA");
  printd_low("%p\n", (void *) ret);
  return ret;
}

static int handle_traps (struct trap_context * ctxt,
                         int * tracee_keep_looking,
                         void * extra);

static void * arena;
#define STREAM stdout

int main (int argc, char * argv[])
{
  if (argc < 2)
    usage(argv[0]);
  tracee = tracee_summon(&argv[1]);
  myarena_dereference = (void *) tracee_deref;
  arena = mainarena_of_pid(tracee->pid);
  const char * symbols[] = {
    "malloc", "realloc", "calloc", "free"
  };
  #define NSYMS (sizeof(symbols) / sizeof(*symbols))
  uintptr_t addresses[NSYMS] = {0};
  const char * raw_binary;
  int fd = open_raw_binary(argv[1], &raw_binary);
  lookup_symbols(addresses, raw_binary, symbols, NSYMS);
  if (!arena)
    arena = (void *) lookup_symbol(raw_binary, "main_arena");
  if (close_raw_binary(fd, raw_binary) < 0)
    failwith("close_raw_binary");
  struct arity function_arity;
  for (int i = NSYMS - 1; i >= 0; --i) {
    if (addresses[i] != 0) {
      switch(i) {
      case 0: /* malloc */
        function_arity.args_number = 1;
        function_arity.returns_void = 0;
        break;
      case 1: /* realloc */
        function_arity.args_number = 2;
        function_arity.returns_void = 0;
        break;
      case 2: /* calloc */
        function_arity.args_number = 2;
        function_arity.returns_void = 0;
        break;
      case 3: /* free */
        function_arity.args_number = 1;
        function_arity.returns_void = 1;
        break;
      }
      tracee_follow_function(tracee,
                             (void *) addresses[i],
                             symbols[i],
                             &function_arity);
    }
  }
  int ret = tracee_main_loop(tracee, handle_traps, NULL);
  tracee_free(tracee);
  return ret;
}

static int handle_traps (struct trap_context * ctxt,
                         int * tracee_keep_looking,
                         void * extra)
{
#if defined(__ARCH__) && __ARCH__ == 64
 #define IP	rip
 #define RET	rax
#else
 #define IP	eip
 #define RET	eax
#endif
  static int count = -1;
  ++count;

  if (ctxt) {	/* Expected SIGTRAP */
    if (ctxt->is_wp) {	/* Function entry */
      fprintf(STREAM, "\n\n");
      fprintf(STREAM, BANNER "Entering function: %s(", ctxt->name);
      if (ctxt->function_arity) {
        size_t args_number = ctxt->function_arity->args_number;
        if (args_number) {
          long * arg_addr = get_sp(tracee);
          for(size_t i = 0; i < args_number - 1; ++i) {
            fprintf(STREAM, "%p, ",
              (void *) ptrace(PTRACE_PEEKDATA, tracee->pid, ++arg_addr, NULL));
          }
          fprintf(STREAM, "%p",
            (void *) ptrace(PTRACE_PEEKDATA, tracee->pid, ++arg_addr, NULL));
        }
      }
      fprintf(STREAM, ")\n");
      if (strcmp("free", ctxt->name) == 0) {
        long * arg_addr = get_sp(tracee);
        void * mem =
          (void *) ptrace(PTRACE_PEEKDATA, tracee->pid, ++arg_addr, NULL);
        fprint_mem_chunk(STREAM, mem, arena);
      }
    } else {	/* Function ret? */
      fprintf(STREAM, BANNER "Returning from function %s(...)\n", ctxt->name);
      if (ctxt->function_arity && !ctxt->function_arity->returns_void)
        fprintf(STREAM,
          BANNER "\\-> returned %p\n", (void *) ctxt->regs.RET);
    }
    fprint_arena(STREAM, arena);
    return 0;
  } else {
    /* fprintf(stderr, BANNER "Warning: child '%s' reached unknown trap at %p.\n",
      tracee->name, (void *) get_ip(tracee));
    getchar(); */
    return EXIT_FAILURE;
  }
}
