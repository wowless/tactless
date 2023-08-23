#include <stdio.h>
#include <stdlib.h>

#include "tactless.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    fputs("usage: tactless product\n", stderr);
    return EXIT_FAILURE;
  }
  tactless *t = tactless_open(argv[1]);
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return EXIT_FAILURE;
  }
  tactless_dump(t);
  tactless_close(t);
  return EXIT_SUCCESS;
}
