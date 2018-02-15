#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#define print(s) write(1, s, sizeof(s) - 1)

#define SIZE 0x18000

int main (int argc, char * argv[])
{
  int n = 0;
  char * msg = "AAAA";
  if (argc >= 2) n = atoi(argv[1]);
  if (argc >= 3) msg = argv[2];
  for (size_t i = 0; i < n; ++i) {
    long * ptr = malloc(SIZE);
    for (size_t j = SIZE / sizeof(long); j; --j)
      ptr[j] = 0xf7f9f780L;
  }
  char * ptr1, * ptr2, * ptr3, * ptr4;
  ptr1 = malloc(0xb);
  ptr2 = malloc(0xb);
  ptr3 = malloc(0xb);
  ptr4 = malloc(0xb);
  strcpy(ptr1, msg);
  free(ptr2);
  // malloc(0x80);
  print("Hello world!\n");
  return 0;
}
