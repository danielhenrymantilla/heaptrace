#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#define print(s) write(1, s, sizeof(s) - 1)

#define SIGTRAP //__asm__("int $0x3");

int main (int argc, char * argv[])
{
  char * ptr = malloc(500);
  char * ptr3;
  {
    char * ptr2 = malloc(200);
    ptr3 = malloc(300);
    free (ptr2);
  }
  ptr = realloc(ptr, 50);
  free(ptr);
  print("Foo!\n");
  ptr = calloc(10, 10);
  print(ptr);
  free(ptr);
  free(ptr3);
/*  SIGTRAP
  char * ptr1, * ptr2, * ptr3, * ptr4, * ptr5;
  ptr1 = malloc(520);
  SIGTRAP
  ptr2 = malloc(520);
  SIGTRAP
  ptr3 = malloc(15);
  SIGTRAP
  ptr2 = realloc(ptr2, 800);
  SIGTRAP
  ptr4 = malloc(520);
  SIGTRAP
  ptr5 = malloc(200);
  SIGTRAP
  free(ptr1);
  SIGTRAP
  free(ptr2);
  SIGTRAP
  free(ptr3);
  SIGTRAP
  ptr3 = malloc(5000);
  SIGTRAP
  free(ptr3); ptr3 = malloc(150); ptr3 = malloc(3000);
  SIGTRAP*/
  //getchar();
  print("Hello world!\n");
  //__asm__("int $0x3");
  return 0;
}
