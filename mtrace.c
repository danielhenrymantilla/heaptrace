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
#if defined(DEBUG) && DEBUG >= 2
  printd_low(BANNER "tracee_deref: *(%p) = ", ptr);
#endif
  long ret = ptrace(PTRACE_PEEKDATA, tracee->pid, ptr, NULL);
  if (ret == -1) failwith("tracee_deref: PTRACE_PEEKDATA");
#if defined(DEBUG) && DEBUG >= 2
  printd_low("%p\n", (void *) ret);
#endif
  return ret;
}

static int handle_traps (struct trap_context * ctxt,
                         int * tracee_keep_looking,
                         void * extra);

static void * main_arena;
#define STREAM stderr

int main (int argc, char * argv[])
{
  if (argc < 2)
    usage(argv[0]);
  tracee = tracee_summon(&argv[1]);
  myarena_dereference = (void *) tracee_deref;
  const char * raw_binary;
  int fd = open_raw_binary(argv[1], &raw_binary);
  main_arena = (void *) lookup_symbol(raw_binary, "main_arena");
  if (!main_arena)
    main_arena = mainarena_of_pid(tracee->pid);
  if (!main_arena)
    print_fail("Couldn't locate main_arena");
  const char * symbols[] = {
    "malloc", "realloc", "calloc", "free"
  };
  #define NSYMS (sizeof(symbols) / sizeof(*symbols))
  uintptr_t addresses[NSYMS] = {0};
  lookup_symbols(addresses, raw_binary, symbols, NSYMS);
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
  mhandle_list mhandles = NULL;
  int ret = tracee_main_loop(tracee, handle_traps, &mhandles);
  tracee_free(tracee);
  return ret;
}

enum fun_id {
  UNDEF, MALLOC, REALLOC, CALLOC, FREE
};

static enum fun_id as_enum (const char * str)
{
  if streq(str, "malloc") return MALLOC;
  if streq(str, "realloc") return REALLOC;
  if streq(str, "calloc") return CALLOC;
  if streq(str, "free") return FREE;
  return UNDEF;
}

static int handle_traps (struct trap_context * ctxt,
                         int * tracee_keep_looking,
                         void * extra)
{
  static int count = -1;
  ++count;

  mhandle_list * at_mhandles = (mhandle_list *) extra;
  if (ctxt) {	/* Known SIGTRAP */
    if (ctxt->is_wp) {	/* Watchpoint => Entry of function */
      fprintf(STREAM, "\n\n");
      fprintf(STREAM, BANNER "Entering function: ");
      trap_fprint_function(ctxt, STREAM);
      fprintf(STREAM, "\n");
      fprint_arena_whole_mem(STREAM, main_arena, *at_mhandles);
      if (streq("free", ctxt->name) || streq("realloc", ctxt->name)) {
        void * mem = (void *) ctxt->args[0];
        printd_var(mem);
        fprint_arena(STREAM, arena_for_mem(mem, main_arena, STREAM));
      } else
        fprint_arena(STREAM, main_arena);
    } else {	/* Function return */
      fprintf(STREAM, BANNER "Returning from function: ");
      trap_fprint_function(ctxt, STREAM);
      long ret   = ctxt->regs.REG_RET;
      long arg_1 = ctxt->args[0];
      long arg_2 = ctxt->args[1];
      if (ctxt->function_arity && !ctxt->function_arity->returns_void) {
        fprintf(STREAM, " = %p", (void *) ret);
      }
      fprintf(STREAM, "\n");
      switch (as_enum(ctxt->name)) {
      case MALLOC:
        mhandles_add(at_mhandles, (void *) ret, (size_t) arg_1);
        break;
      case REALLOC:
        mhandles_add(at_mhandles, (void *) arg_1, (size_t) 0);
        mhandles_add(at_mhandles, (void *) ret, (size_t) arg_2);
        break;
      case CALLOC:
        mhandles_add(at_mhandles, (void *) ret,
                                  (size_t) arg_1 * (size_t) arg_2);
        break;
      case FREE:
        mhandles_add(at_mhandles, (void *) arg_1, (size_t) 0);
        break;
      default: break;
      }
    }
    return 0;
  } else {
    printd(BANNER "Warning: child '%s' reached unknown trap at %p.\n",
      tracee->name, (void *) get_ip(tracee));
    return EXIT_FAILURE;
  }
}
