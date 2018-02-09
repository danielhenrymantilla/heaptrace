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

#define BANNER "<tracer> "

/* Use make D=DEBUG when compiling to enable debug printing */
#ifdef DEBUG
 #define printd(format, ...) \
  fprintf(stderr, "\e[33m" format "\e[m", ##__VA_ARGS__)
 #define printd_low(format, ...) \
  fprintf(stderr, "\e[1;30m" format "\e[m", ##__VA_ARGS__)
#else
 #define printd(...) ((void) 0)
 #define printd_low(...) ((void) 0)
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

#endif /* __HELPERS_H__ */
