#include "helpers.h"
#include "elfutils.h"

#if defined(__ARCH__) && __ARCH__ == 64
 #define ELF_SYM	Elf64_Sym
 #define ELF_EHDR	Elf64_Ehdr
 #define ELF_PHDR	Elf64_Phdr
 #define ELF_SHDR	Elf64_Shdr
 #define ELF_DYN 	Elf64_Dyn
#else
 #define ELF_SYM	Elf32_Sym
 #define ELF_EHDR	Elf32_Ehdr
 #define ELF_PHDR	Elf32_Phdr
 #define ELF_SHDR	Elf32_Shdr
 #define ELF_DYN 	Elf32_Dyn
#endif
#define ELFMAGIC	0x464c457f	/* '\x7f' 'ELF' */

#ifndef print_fail
 #define print_fail(fmt, ...) do {				\
   fprintf(stderr, "Fatal error: " fmt ".\n", ##__VA_ARGS__);	\
   exit(-1);							\
 } while (0)
#endif

#define streq(s1, s2) (!strcmp(s1, s2))

int open_raw_binary (const char * binaryname, const char ** raw_binary_addr)
{
  if (!raw_binary_addr)
    print_fail("open_raw_binary requires non-NULL second arg");
  int fd;
  if ((fd = open(binaryname, O_RDONLY)) < 0) failwith("open");
  struct stat st;
  if (fstat(fd, &st) < 0) failwith("fstat");
  void * raw_binary = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (raw_binary == MAP_FAILED) failwith("mmap");
  *raw_binary_addr = (const char *) raw_binary;
  return fd;
}

int close_raw_binary (int fd, const char * raw_binary)
{
  struct stat st;
  if (fstat(fd, &st) < 0) return -1;
  if (munmap((void *)raw_binary, st.st_size) < 0) return -1;
  if (close(fd) < 0) return -1;
  return 0;
}

uintptr_t lookup_symbol (const char * raw_binary, const char * symbol) {
  uintptr_t ret;
  lookup_symbols(&ret, raw_binary, &symbol, 1);
  return ret;
}

static ELF_EHDR get_headers(const ELF_PHDR ** phdr,
                            const ELF_SHDR ** shdr,
                            const char * raw_binary)
{
  ELF_EHDR ehdr = *(ELF_EHDR *) raw_binary;
  *phdr = (const ELF_PHDR *) &raw_binary[ehdr.e_phoff];
  *shdr = (const ELF_SHDR *) &raw_binary[ehdr.e_shoff];

  if (*(uint32_t *) raw_binary != ELFMAGIC)
    print_fail("Not an ELF file (Magic failed, got 0x%08x)",
      *(uint32_t *) raw_binary);
  if (ehdr.e_type != ET_EXEC)
    print_fail("Not an executable (got %#hx instead of ET_EXEC = %#hx)",
      ehdr.e_type, ET_EXEC);
  if (ehdr.e_shstrndx == 0 || ehdr.e_shoff == 0 || ehdr.e_shnum == 0)
    print_fail("missing section header table");
  return ehdr;
}

static uintptr_t lookup_dynamic_symbol (const char * raw_binary,
                                        const char * symbol_name)
{
  printd("Looking up dynamic symbol '%s'...\n", symbol_name);
  static uintptr_t plt_section_addr = (uintptr_t) NULL;
  static const char * dynstr_section_addr = NULL;
  static const ELF_SYM * dynsym_section_addr = NULL;
  static size_t dynsym_section_size = 0;
  /* char plt_entry[] = {
    0xff, 0x25, 0x0c, 0xa0, 0x04, 0x08,		// jmp *got_entry_addr
    0x68, 0x00, 0x00, 0x00, 0x00,		// push $index
    0xe9, 0xe0, 0xff, 0xff, 0xff		// jmp $addr
  } */
  #define PLT_ENTRY_SZ 0x10			/* sizeof(plt_entry) */

  const ELF_PHDR * phdr;
  const ELF_SHDR * shdr;
  const ELF_EHDR ehdr = get_headers(&phdr, &shdr, raw_binary);

  if (!dynstr_section_addr || !plt_section_addr || !dynsym_section_addr) {
    const char * section_names_table =		/* string table */
      &raw_binary[shdr[ehdr.e_shstrndx].sh_offset];
    for (size_t i = 0; i < ehdr.e_shnum; ++i) {
      if (shdr[i].sh_type == SHT_STRTAB
        && streq(".dynstr", &section_names_table[shdr[i].sh_name]))
      {
        printd("Found .dynstr at offset %p\n", (void *) shdr[i].sh_offset);
        dynstr_section_addr = &raw_binary[shdr[i].sh_offset];
      } else if (shdr[i].sh_type == SHT_PROGBITS
        && streq(".plt", &section_names_table[shdr[i].sh_name]))
      {
        printd("Found .plt at offset %p and address %p\n",
          (void *) shdr[i].sh_offset, (void *) shdr[i].sh_addr);
        plt_section_addr = (uintptr_t) shdr[i].sh_addr;
      } else if (shdr[i].sh_type == SHT_DYNSYM
        && streq(".dynsym", &section_names_table[shdr[i].sh_name]))
      {
        printd("Found .dynsym at offset %p\n", (void *) shdr[i].sh_offset);
        dynsym_section_addr = (ELF_SYM *) &raw_binary[shdr[i].sh_offset];
        dynsym_section_size = (size_t) shdr[i].sh_size;
      }
    }
  }

  if (!dynstr_section_addr)
    print_fail("lookup_dynamic_symbol: couldn't locate .dynstr section");
  if (!dynsym_section_addr)
    print_fail("lookup_dynamic_symbol: couldn't locate .dynsym section");
  if (!plt_section_addr)
    print_fail("lookup_dynamic_symbol: couldn't locate .plt section");

  uintptr_t ret = plt_section_addr;
  const ELF_SYM * cur_dynsym = dynsym_section_addr;
  for (size_t i = 0; i < dynsym_section_size; i += sizeof(ELF_SYM)) {
    printd_low("dynsym entry number %p : '%s'\n",
      (void *) ((ret - plt_section_addr) / PLT_ENTRY_SZ),
      dynstr_section_addr + cur_dynsym->st_name);
    if ((cur_dynsym->st_info & 0xf) == STT_FUNC)
      ret += PLT_ENTRY_SZ;
    if (streq(symbol_name, dynstr_section_addr + cur_dynsym->st_name))
      return ret;
    ++cur_dynsym;
  }

  //print_fail("Couldn't locate dynamic symbol '%s'", symbol_name);
  fprintf(stderr, "Couldn't locate dynamic symbol '%s'.\n", symbol_name);
  return (uintptr_t) NULL;
}

void lookup_symbols (uintptr_t * addresses,
                     const char * raw_binary,
                     const char ** symbols,
                     size_t n)
{
  const ELF_PHDR * phdr;
  const ELF_SHDR * shdr;
  ELF_EHDR ehdr = get_headers(&phdr, &shdr, raw_binary);

  size_t * lens;
  lens = (size_t *) malloc(n * sizeof(*lens));
  if (lens == NULL) failwith("malloc");

  for (size_t k = 0; k < n; ++k) {
    addresses[k] = (uintptr_t) NULL;
    lens[k] = strlen(symbols[k]);
  }

  for (size_t i = 0; i < ehdr.e_shnum; ++i) {
    if (shdr[i].sh_type == SHT_SYMTAB) {
      ELF_SYM * symtab = (ELF_SYM *)
        &raw_binary[ shdr[ i               ].sh_offset ];
      const char * strtab =			/* i -> shdr[i].sh_link */
        &raw_binary[ shdr[ shdr[i].sh_link ].sh_offset ];
      for (size_t j = 0; j < shdr[i].sh_size / sizeof(ELF_SYM); ++j) {
        for (size_t k = 0; k < n; ++k) {
          const char * symname = &strtab[symtab->st_name];
          if (strncmp(symname, symbols[k], lens[k]) == 0) {
            printd_low("Found symbol '%s' for '%s'.\n", symname, symbols[k]);
            char next_char = symname[lens[k]];
            if (next_char == '\0') {		/* exact match */
              addresses[k] = (uintptr_t) symtab->st_value;
              printd("%s at %p\n", symbols[k], (void *) addresses[k]);
            } else if (next_char == '@') {	/* partial match, dynsym ? */
              printd("'%s' seems to be a dynamically linked symbol\n",
                symname);
              addresses[k] = lookup_dynamic_symbol(raw_binary, symbols[k]);
              printd("%s at %p\n", symbols[k], (void *) addresses[k]);
            }
          }
        }
        ++symtab;
      }
    }
  }
  free(lens);
}
