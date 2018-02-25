#ifndef __PRINTUTILS_H__
#define __PRINTUTILS_H__

#define STREAM stderr

#define LINE_SEP "========================="

/* hex int token */
#if defined(__ARCH__) && __ARCH__ == 64
# define XT		"0x%lx"
#else
# define XT		"0x%x"
#endif

/* hex byte token */
#define BT		"0x%02hhx"

#ifdef WITH_HTML
# include "printutils_html.h"

# define printf_console(format, ...)					\
 do {									\
  if (print_mode & PRINT_CONSOLE) {					\
    fprintf(STREAM, format, ##__VA_ARGS__);				\
  }									\
} while (0)

# define printf_line(format, ...) 					\
 do {									\
  printf_console(format, ##__VA_ARGS__);				\
  printf_console("\n");							\
  if(print_mode & PRINT_HTML) {						\
    html_printf_line(format, ##__VA_ARGS__);				\
  }									\
 } while (0)

# define print_short(s) 						\
 do {									\
  printf_console("%s", s);						\
  if(print_mode & PRINT_HTML) {						\
    html_printf_short(s);						\
  }									\
 } while (0)

#else

# define printf_console(format, ...)					\
 do {									\
  fprintf(STREAM, format, ##__VA_ARGS__);				\
  fprintf(STREAM, "\n");						\
 } while (0)

# define printf_line(...) printf_console(__VA_ARGS__)

# define print_short(s) fprintf(STREAM, "%s", s)

#endif

#endif /* __PRINTUTILS_H__ */
