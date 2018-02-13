EXE=mtrace

ARGS=example/foo

ARCH=32

ifneq ($(D), )
CUSTOMDEFINE=-D '$(D)'
endif
# CPP var definition of offset to main_arena symbol.
ifeq ($(ARCH), 32)
DEFOFFSET=-D LIBC_MAINARENA_OFF=0x`python2.7 -c 'from sys import argv; print argv[1][-3:]' $$(nm /usr/lib/debug/lib/i386-linux-gnu/libc-2.23.so | grep main_arena)`
else
DEFOFFSET=-D LIBC_MAINARENA_OFF=0x`python2.7 -c 'from sys import argv; print argv[1][-3:]' $$(nm /usr/lib/debug/lib/x86_64-linux-gnu/libc-2.23.so | grep main_arena)`
endif

CFLAGS=-Wall -Wextra -m$(ARCH) -D __ARCH__=$(ARCH) $(CUSTOMDEFINE)

LDFLAGS=-Iinclude

.PHONY: all set clean run $(ARGS)

all: set clean run

run: $(EXE) $(ARGS)
	 ./$< $(ARGS)

$(ARGS): $(ARGS).c
	@make -C example foo ARCH=$(ARCH)

$(EXE): $(EXE).o elfutils.o myarena.o tracee.o myprinter.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(EXE).o: $(EXE).c
	$(CC) $(CFLAGS) $(DEFOFFSET) -c $<

%.o: include/%.c
	$(CC) $(CFLAGS) -c $<

set: include/myarena.c $(EXE).c
	@nano $^

clean:
	@rm -f $(EXE) *.o *~ core
	@ls
	@rm -f example/foo example/core
