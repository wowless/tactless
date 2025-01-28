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

struct dump_command {
  const char *name;
  int (*fn)(const unsigned char *, size_t);
};

const struct dump_command dump_commands[] = {
    {"root", dump_root},
    {"encoding", dump_encoding},
    {"archive_index", dump_archive_index},
    {0, 0},
};

static int dump(int argc, char **argv) {
  if (argc != 2) {
    fputs("usage: tactless dump $format $filename\n", stderr);
    return 0;
  }
  size_t size;
  unsigned char *text = tactless_readfile(argv[1], &size);
  if (!text) {
    fputs("error reading file\n", stderr);
    return 0;
  }
  for (const struct dump_command *c = dump_commands; c->name; ++c) {
    if (strcmp(argv[0], c->name) == 0) {
      int ret = c->fn(text, size);
      free(text);
      return ret;
    }
  }
  fputs("invalid type\n", stderr);
  free(text);
  return 0;
}

static int fdid(int argc, char **argv) {
  if (argc != 2) {
    fputs("usage: tactless fdid $product $fdid\n", stderr);
    return 0;
  }
  tactless *t = tactless_open(argv[0], 0);
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return 0;
  }
  size_t size;
  unsigned char *data = tactless_get_fdid(t, atoi(argv[1]), &size);
  if (!data) {
    tactless_close(t);
    return 0;
  }
  int ret = fwrite(data, size, 1, stdout) == size;
  tactless_close(t);
  return ret;
}

static int name(int argc, char **argv) {
  if (argc != 2) {
    fputs("usage: tactless name $product $name\n", stderr);
    return 0;
  }
  tactless *t = tactless_open(argv[0], 0);
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return 0;
  }
  size_t size;
  unsigned char *data = tactless_get_name(t, argv[1], &size);
  if (!data) {
    tactless_close(t);
    return 0;
  }
  int ret = fwrite(data, size, 1, stdout) == size;
  tactless_close(t);
  return ret;
}

static int build(int argc, char **argv) {
  if (argc != 1) {
    fputs("usage: tactless build $product\n", stderr);
    return 0;
  }
  char build[33];
  if (!tactless_current_build(argv[0], build)) {
    return 0;
  }
  puts(build);
  return 1;
}

static int summary(int argc, char **argv) {
  if (argc < 1 || argc > 2) {
    fputs("usage: tactless summary $product [$hash]\n", stderr);
    return 0;
  }
  const char *build_config = 0;
  if (argc == 2) {
    build_config = argv[1];
  }
  tactless *t = tactless_open(argv[0], build_config);
  if (!t) {
    fputs("error opening tactless\n", stderr);
    return 0;
  }
  tactless_dump(t);
  tactless_close(t);
  return 1;
}

struct command {
  const char *name;
  int (*fn)(int, char **);
};

const struct command commands[] = {
    {"build", build}, {"dump", dump},       {"fdid", fdid},
    {"name", name},   {"summary", summary}, {0, 0},
};

int main(int argc, char **argv) {
  if (argc < 2) {
    fputs("usage: tactless command ...\n", stderr);
    return EXIT_FAILURE;
  }
  for (const struct command *c = commands; c->name; ++c) {
    if (strcmp(argv[1], c->name) == 0) {
      return c->fn(argc - 2, argv + 2) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  }
  fputs("unknown command\n", stderr);
  return EXIT_FAILURE;
}
