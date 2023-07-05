#include <stdlib.h>
#include <stdio.h>
#include "tactless.h"

int main(int argc, char **argv) {
  tactless *t = tactless_open();
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return EXIT_FAILURE;
  }
  puts("Hello, world!");
  tactless_close(t);
  return EXIT_SUCCESS;
}
