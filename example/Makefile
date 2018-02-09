EXE=foo

ARCH=32

CFLAGS=-m$(ARCH) #-static

.PHONY: all set clean run

all: set clean run

run: $(EXE)
	 ./$<

$(EXE): $(EXE).c
	$(CC) $(CFLAGS) -o $@ $<

set: $(EXE).c
	@nano $<

clean:
	@rm -f $(EXE) *.o *~
