#include "myprinter.h"
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>

static void write_hex(char * dst, unsigned long long x, int len)
{
  dst += len;
  for (int i = 0; i < len - 2; ++i) {
    int digit = x & 0xf;
    *(--dst) = digit > 9 ? digit - 10 + 'a' : digit + '0';
    x = x >> 4;		/* nibble by nibble */
  }
  if (len >= 2)
    *(--dst) = 'x';
  if (len >= 1)
    *(--dst) = '0';
}

void __myfprintf__(FILE * stream, char * myformat, ...)
{
  va_list ap;
  va_start(ap, myformat);
  size_t i = 0; char c;
  while((c = myformat[i]) != '\0') {
    if (c == '%') {
      int len = (myformat[i + 1] == 'b') ? BT_LEN : XT_LEN;
      write_hex(myformat + i, (unsigned long long) va_arg(ap, uintptr_t), len);
      i += len;
    } else {
      ++i;
    }
  }
  va_end(ap);
  write(fileno(stream), myformat, i);
}
