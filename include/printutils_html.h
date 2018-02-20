#ifndef __PRINTUTILS_HTML_H__
#define __PRINTUTILS_HTML_H__
#include <stdarg.h>

# define PRINT_CONSOLE  1       /* 1 << 0 */
# define PRINT_HTML     2       /* 1 << 1 */

int print_mode /* = PRINT_CONSOLE by default */ ;

void html_init (const char * filename);
void html_close ();

void html_set_coordinates (size_t x, size_t y);

void html_printf_short (const char *);
void html_printf_line (const char * fmt, ...);

#endif /* __PRINTUTILS_HTML_H__ */

