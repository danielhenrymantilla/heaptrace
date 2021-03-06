EXE=heaptrace

ARGS=example/foo

ARCH=32

DEBUG=0
COLOR=YES
HTML=YES

CFLAGS=-Wall -Wextra \
  -m$(ARCH) -D __ARCH__=$(ARCH) \
  $(COLORDEF) $(DEBUGDEF) $(HTMLDEF)

LDFLAGS=#-Iinclude

.PHONY: default all set clean run no_obj

default: $(EXE) no_obj

all: set clean run

run: $(EXE) example/foo
	 ./$< $(ARGS)

example/foo: example/foo.c
	@make -C example foo ARCH=$(ARCH)

ifeq ($(HTML), YES)
HTMLDEP=printutils_html.o
HTMLDEF=-D WITH_HTML
endif

$(EXE): $(EXE).o elfutils.o heaputils.o tracee.o $(HTMLDEP) opthandler.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(EXE).o: $(EXE).c
	$(CC) $(CFLAGS) $(DEFOFFSET) -c $<

opthandler.o: include/opthandler/opthandler.c
	$(CC) $(CFLAGS) -c $<

%.o: include/%.c
	$(CC) $(CFLAGS) -c $<

set: $(EXE).c include/printutils_html.c
	@nano $^

no_obj:
	@rm -f *.o

clean: no_obj
	@rm -f $(EXE) *~ core .gdb_history
	@ls
	@rm -f example/foo example/core


ifeq ($(COLOR), YES)
COLORDEF=-D COLOR
endif

ifneq ($(DEBUG), 0)
DEBUGDEF=-D 'DEBUG=$(DEBUG)'
endif

# CPP var definition of offset to main_arena symbol.
ifeq ($(ARCH), 32)
DEFOFFSET=-D LIBC_MAINARENA_OFF=0x`python2.7 -c 'from sys import argv; print argv[1][-3:]' $$(nm /usr/lib/debug/lib/i386-linux-gnu/libc-2.23.so | grep main_arena)`
else
DEFOFFSET=-D LIBC_MAINARENA_OFF=0x`python2.7 -c 'from sys import argv; print argv[1][-3:]' $$(nm /usr/lib/debug/lib/x86_64-linux-gnu/libc-2.23.so | grep main_arena)`
endif
