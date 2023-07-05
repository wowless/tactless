#include <stdlib.h>
#include <stdio.h>
#include "tactless.h"

int main(int argc, char **argv) {
  tactless *t = tactless_open();
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return EXIT_FAILURE;
  }
  tactless_dump(t);
  tactless_close(t);
  return EXIT_SUCCESS;
}
