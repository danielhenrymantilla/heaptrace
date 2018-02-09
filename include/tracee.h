#ifndef __TRACEE_H__
#define __TRACEE_H__

#include <sys/types.h>

typedef struct bp_node * bp_list;

typedef struct tracee {
  const char *	name;
  pid_t		pid;
  bp_list	bps;
} tracee_t;

tracee_t * tracee_summon (char * const args[]);
tracee_t * tracee_attach (pid_t);

struct arity {
  size_t	args_number;
  int		returns_void;
};

/* Add a watchpoint: breakpoint at entry and exit of given function */
void tracee_follow_function (tracee_t *		tracee,
                             void *		function_addr,
                             const char *	function_name,
                             struct arity *	function_arity);

void tracee_unfollow_function (tracee_t *, void *);

struct trap_context {
  const char *			name;
  struct arity *		function_arity;
  int				is_wp;
  struct user_regs_struct	regs;
};
/*
   Wrapper to handle SIGTRAPS in a 'while (*tracee_keep_looping)' loop:
   For that, define a function that can use:
   - a 'struct trap_context * ctxt' to get the function name and the registers;
      ( \-> This will be NULL for unexpected traps )
   - a reference to the 'tracee_keep_looping' control loop var;
   - a 'void * extra' parameter to pass any extra stuff (use NULL to skip)
      ( \-> for instance with a pointer to some custom structure )
*/
int tracee_main_loop (tracee_t * tracee,
                      int (*handle_traps) (struct trap_context * ctxt,
                                           int * tracee_keep_looping,
                                           void * extra),
                      void * extra);

void tracee_free (tracee_t *);

void * get_ip(tracee_t *);
void * get_sp(tracee_t *);

#endif /* __TRACEE_H__ */
