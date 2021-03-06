#include "heaptrace.h"

enum options_order {
  o_OUTPUT_DIRECTORY,
  o_HTML,
  o_PAUSES,
  o_DEBUG,
  o_NO_COLOR,
};

static struct opthandler_option options[] = {
  [o_HTML] = {
    "replace raw-text output to pretty printed HTML",
    'h',	"html",			NULL,		arg_flag},
  [o_OUTPUT_DIRECTORY] = {
    "set the output directory",
    'd',	NULL/*"output-dir"*/,	"dirname",	arg_default("output")},
  [o_DEBUG] = {
    "enable printing debug info to stderr",
    'g',	"debug",		NULL,		arg_flag},
  [o_NO_COLOR] = {
    "disable colored output in console",
    '\0',	"no-color",		NULL,		arg_flag},
  [o_PAUSES] = {
    "enable pauses during console printing",
    'p',	"pauses",		NULL,		arg_flag},
};

static void maybe_pause (void)
{
  if (options[o_PAUSES].value.flag) getchar();
}

static tracee_t * tracee;

static long tracee_deref (void * ptr)
{
#if defined(DEBUG) && DEBUG >= 2
  printd_low(BANNER "tracee_deref: *(%p) = ", ptr);
#endif
  long ret = ptrace(PTRACE_PEEKDATA, tracee->pid, ptr, NULL);
  /* if (ret == -1) failwith("tracee_deref: PTRACE_PEEKDATA"); */
#if defined(DEBUG) && DEBUG >= 2
  printd_low("%p\n", (void *) ret);
#endif
  return ret;
}

static int handle_traps (struct trap_context * ctxt,
                         int * tracee_keep_looking,
                         void * extra);

static void * main_arena;

int main (int argc, char * argv[])
{
  opthandler_help_char = '?';
  opthandler_argsname = "command [args ...]";
  opthandler_init(sizeof(options) / sizeof(*options),
                 options,
                 "Program to trace and print the contents of the heap "
                 "at each malloc, free, calloc or realloc call.");
  opthandler_handle_opts(&argc, &argv);
  flag_nocolor = options[o_NO_COLOR].value.flag;
  flag_debug = options[o_DEBUG].value.flag;
  if (!argc) {
    fprintf(stderr, "Error, missing command.\n");
    opthandler_usage(EXIT_FAILURE);
  }

  opthandler_free();
  tracee = tracee_summon(argv);
  heaputils_dereference = (void *) tracee_deref;

  const char * raw_binary;
  int fd = open_raw_binary(argv[0], &raw_binary);
  const char * symbols[5] = {
    "main_arena",
    "malloc", "realloc", "calloc", "free"
  };
  uintptr_t addresses[5] = {0};
  lookup_symbols(addresses, raw_binary, symbols, 5);
  if (close_raw_binary(fd, raw_binary) < 0)
    failwith("close_raw_binary");
  main_arena = (void *) addresses[0];
  if (!main_arena)
    main_arena = mainarena_of_pid(tracee->pid);
  if (!main_arena)
    print_fail("Couldn't locate main_arena");
  struct arity function_arity;
  for (size_t i = 1; i <= 4; ++i) {
    if (addresses[i] != 0) {
      switch(i) {
      case 1: /* malloc */
        function_arity.args_number = 1;
        function_arity.returns_void = 0;
        break;
      case 2: /* realloc */
        function_arity.args_number = 2;
        function_arity.returns_void = 0;
        break;
      case 3: /* calloc */
        function_arity.args_number = 2;
        function_arity.returns_void = 0;
        break;
      case 4: /* free */
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
  mhandles_free(mhandles);
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
      maybe_pause();
      print_arena_whole_mem(main_arena, *at_mhandles);
      maybe_pause();
      if (streq("free", ctxt->name) || streq("realloc", ctxt->name)) {
        void * mem = (void *) ctxt->args[0];
        printd_var(mem);
        print_arena(arena_for_mem(mem, main_arena));
      } else
        print_arena(main_arena);
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
      maybe_pause();
      switch (as_enum(ctxt->name)) {
      case MALLOC:
        mhandles_add(at_mhandles, (void *) ret, (size_t) arg_1);
        break;
      case REALLOC:
        mhandles_add(at_mhandles, (void *) ret, (size_t) arg_2);
        if (!arg_1) break;	/* realloc(NULL, ...) <=> malloc(...) */
        if (arg_1 != ret) {	/* arg_1 has been freed */
          mhandles_add(at_mhandles, (void *) arg_1, (size_t) 0);
          fprintf(STREAM,
            "realloc has freed the pointer %p.\n", (void *) arg_1);
          print_mem((void *) arg_1, main_arena);
        } else {
          size_t old_size = 0;
          for (mhandle_list mhandles = *at_mhandles;
               mhandles != NULL;
               mhandles = mhandles->next)
          {
            if (mhandles->usr_addr == (void *) arg_1) {
              old_size = mhandles->usr_size;
              break; /* break the for loop */
            }
          }
          size_t chunk_new_size = request2size(arg_2);
          if (chunk_new_size < request2size(old_size)) {
            void * next_chunk = (void *) mem2chunk(arg_1) + chunk_new_size;
            fprintf(STREAM,
              "realloc might have freed or coalesced at %p:\n", next_chunk);
            print_mem(chunk2mem(next_chunk), main_arena);
          }
        }
        break;
      case CALLOC:
        mhandles_add(at_mhandles, (void *) ret,
                                  (size_t) arg_1 * (size_t) arg_2);
        break;
      case FREE:
        mhandles_add(at_mhandles, (void *) arg_1, (size_t) 0);
        print_mem((void *) arg_1, main_arena);
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
