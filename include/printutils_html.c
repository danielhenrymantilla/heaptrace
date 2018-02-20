#include "helpers.h" /* TODO: remove */
#include "printutils_html.h"

int print_mode = PRINT_CONSOLE;

/* HTML-SVG parameters: coordinates + FILE stream */
static struct {
  size_t        x;
  size_t        y;
  size_t        next_x;
  size_t        next_y;
  FILE *        stream;
} params;

void html_init (const char * filename)
{
  // TODO
}

void html_close ()
{
  // TODO
}

void html_set_coordinates (size_t x, size_t y)
{
  // TODO
}

void html_printf_short (const char * s)
{
  // TODO
}

void html_printf_line (const char * fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  va_end(args);
}

