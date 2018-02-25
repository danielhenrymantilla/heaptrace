#ifndef __HELPERS_H__
#define __HELPERS_H__

#define _GNU_SOURCE

#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <err.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#include "printutils.h"

#define BANNER "<tracer> "

/* Colored printing can be enabled / disabled throught the flag_nocolor var */
int flag_nocolor;
#define COLOR_OPEN		(flag_nocolor ? "" : "\e[33m")
#define COLOR_OPEN_SECONDARY	(flag_nocolor ? "" : "\e[1;30m")
#define COLOR_CLOSE		(flag_nocolor ? "" : "\e[m")

/*************************************************************************
 ***** Print Debug (= printd) and Verbose Print Debug (= printd_low) *****
 *************************************************************************
 *                                                                       *
 * 1) Print Debug can be dynamically enabled through the flag_debug var; *
 *                                                                       *
 * 2) When compiling, you may use:                                       *
 *      -> make DEBUG=1 to force enabling Print Debug;                   *
 *      -> make DEBUG=2 to enable Verbose Print Debug;                   *
 *                                                                       *
 *************************************************************************/
int flag_debug;

#ifdef DEBUG
# define printd(format, ...) \
    fprintf(stderr, "%s" format "%s", \
      COLOR_OPEN, ##__VA_ARGS__, COLOR_CLOSE)

# define printd_low(format, ...) \
    fprintf(stderr, "%s" format "%s", \
      COLOR_OPEN_SECONDARY, ##__VA_ARGS__, COLOR_CLOSE)
#else
# define printd(format, ...) \
    do { \
      if (flag_debug) \
        fprintf(stderr, "%s" format "%s", \
          COLOR_OPEN, ##__VA_ARGS__, COLOR_CLOSE); \
    } while (0)

# define printd_low(...) ((void) 0)
#endif

#define xstr(x) #x	/* To expand beyond macros */
#define printd_var(var) printd("%s = %p\n", #var, (void *)(var))

/* 'failwith' complements 'perror'. For other fatal errors, use 'print_fail' */
#define failwith(fmt, ...) \
  do { \
    char * buf = NULL; \
    asprintf(&buf, BANNER fmt, ##__VA_ARGS__); \
    perror(buf); \
    free(buf); \
    exit(EXIT_FAILURE); \
  } while (0)
#define print_fail(fmt, ...) \
  do { \
    fprintf(stderr, "Fatal error: " fmt ".\n", ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
  } while (0)

#define streq(s1, s2) (!strcmp(s1, s2))

#endif /* __HELPERS_H__ */
