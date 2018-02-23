#ifndef __MTRACE_H__
#define __MTRACE_H__

#include "include/helpers.h"
#include "include/opthandler/opthandler.h"
#include "include/tracee.h"
#include "include/mymalloc.h"
#include "include/heaputils.h"
#include "include/elfutils.h"

extern char ** environ;

extern void * heaputils_dereference;

extern char * opthandler_argsname;

extern char opthandler_help_char;

#endif /* __MTRACE_H__ */
