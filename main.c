#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tactless.h"

static int dump_root(const unsigned char *text, size_t size) {
  struct tactless_root r;
  if (!tactless_root_parse(text, size, &r)) {
    fputs("parse error\n", stderr);
    return 0;
  }
  tactless_root_dump(&r);
  tactless_root_free(&r);
  return 1;
}

static int dump_encoding(const unsigned char *text, size_t size) {
  struct tactless_encoding e;
  if (!tactless_encoding_parse(text, size, &e)) {
    fputs("parse error\n", stderr);
    return 0;
  }
  tactless_encoding_dump(&e);
  tactless_encoding_free(&e);
  return 1;
}

static int dump_archive_index(const unsigned char *text, size_t size) {
  struct tactless_archive_index a;
  if (!tactless_archive_index_parse(text, size, &a)) {
    fputs("parse error\n", stderr);
    return 0;
  }
  tactless_archive_index_dump(&a);
  tactless_archive_index_free(&a);
  return 1;
}

static int dump(const char *type, const char *filename) {
  size_t size;
  unsigned char *text = tactless_readfile(filename, &size);
  if (!text) {
    return 0;
  }
  int ret = 1;
  if (strcmp(type, "root") == 0) {
    ret = dump_root(text, size);
  } else if (strcmp(type, "encoding") == 0) {
    ret = dump_encoding(text, size);
  } else if (strcmp(type, "archive_index") == 0) {
    ret = dump_archive_index(text, size);
  } else {
    fputs("invalid type\n", stderr);
    ret = 0;
  }
  free(text);
  return ret;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "dump") == 0) {
    return dump(argv[2], argv[3]) ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  if (argc == 4 && strcmp(argv[1], "fdid") == 0) {
    tactless *t = tactless_open(argv[2], 0);
    if (!t) {
      fputs("error opening tactless\n", stderr);
      return EXIT_FAILURE;
    }
    size_t size;
    unsigned char *data = tactless_get_fdid(t, atoi(argv[3]), &size);
    if (!data) {
      tactless_close(t);
      return EXIT_FAILURE;
    }
    int ret =
        fwrite(data, size, 1, stdout) == size ? EXIT_SUCCESS : EXIT_FAILURE;
    tactless_close(t);
    return ret;
  }
  if (argc == 4 && strcmp(argv[1], "name") == 0) {
    tactless *t = tactless_open(argv[2], 0);
    if (!t) {
      fputs("error opening tactless\n", stderr);
      return EXIT_FAILURE;
    }
    size_t size;
    unsigned char *data = tactless_get_name(t, argv[3], &size);
    if (!data) {
      tactless_close(t);
      return EXIT_FAILURE;
    }
    int ret =
        fwrite(data, size, 1, stdout) == size ? EXIT_SUCCESS : EXIT_FAILURE;
    tactless_close(t);
    return ret;
  }
  if (argc != 2 && argc != 3) {
    fputs("usage: tactless product\n", stderr);
    return EXIT_FAILURE;
  }
  const char *build_config = 0;
  if (argc == 3) {
    build_config = argv[2];
  }
  tactless *t = tactless_open(argv[1], build_config);
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return EXIT_FAILURE;
  }
  tactless_dump(t);
  tactless_close(t);
  return EXIT_SUCCESS;
}
