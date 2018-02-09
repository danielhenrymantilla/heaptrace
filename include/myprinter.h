/*
	Custom basic implementation of formated printing
	to avoid dynamic memory allocation
*/
#ifndef __MYPRINTER_H__
#define __MYPRINTER_H__

#include <stdio.h>

#if defined(__ARCH__) && __ARCH__ == 64
 #define __HEX_TOKEN__	"%xdeadbeefdeadbeef"
#else
 #define __HEX_TOKEN__	"%xdeadbeef"
#endif
#define XT		__HEX_TOKEN__
#define XT_LEN		(sizeof(XT) - 1)

#define __BYTE_TOKEN__	"%b42"
#define BT		__BYTE_TOKEN__
#define BT_LEN		(sizeof(BT) - 1)

void __myfprintf__(FILE * stream, char * myformat, ...);

#define myfprintf(stream, fmt_ro, ...) do { \
  char fmt[] = fmt_ro; __myfprintf__(stream, fmt, ##__VA_ARGS__); \
} while(0)

#define myprintf(...)	myfprintf(stdout, __VA_ARGS__)

#endif /* __MYPRINTER_H__ */
