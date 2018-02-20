#ifndef __HELPERS_H__
#define __HELPERS_H__

#define _GNU_SOURCE
#define DISABLE_MYPRINTER

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

#define BANNER "<tracer> "

/* Use make COLOR=0 when compiling to disable colored console printing */
#ifdef COLOR
# define COLOR_OPEN "\e[33m"
# define COLOR_OPEN_SECONDARY "\e[1;30m"
# define COLOR_CLOSE "\e[m"
#else
# define COLOR_OPEN ""
# define COLOR_OPEN_SECONDARY ""
# define COLOR_CLOSE ""
#endif

/* Use make DEBUG=1 when compiling to enable debug printing */
#ifdef DEBUG
# define printd(format, ...) \
  fprintf(stderr, COLOR_OPEN format COLOR_CLOSE, ##__VA_ARGS__)
# define printd_low(format, ...) \
  fprintf(stderr, COLOR_OPEN_SECONDARY format COLOR_CLOSE, ##__VA_ARGS__)
#else
# define printd(...) ((void) 0)
# define printd_low(...) ((void) 0)
#endif

#define xstr(x) #x
#define printd_var(var) printd("%s = %p\n", #var, (void *)(var))

#define failwith(fmt, ...) do { \
  char * buf = NULL; \
  asprintf(&buf, BANNER fmt, ##__VA_ARGS__); \
  perror(buf); \
  free(buf); \
  exit(EXIT_FAILURE); \
} while (0)

#ifndef print_fail
# define print_fail(fmt, ...) do {                              \
   fprintf(stderr, "Fatal error: " fmt ".\n", ##__VA_ARGS__);   \
   exit(-1);                                                    \
 } while (0)
#endif

#define streq(s1, s2) (!strcmp(s1, s2))

#endif /* __HELPERS_H__ */
