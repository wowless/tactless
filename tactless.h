#ifndef TACTLESS_H_
#define TACTLESS_H_

#include <stddef.h>

struct tactless;
typedef struct tactless tactless;

tactless *tactless_open(const char *product);
void tactless_close(tactless *t);
void tactless_dump(const tactless *t);

struct tactless_encoding {
  unsigned char *data;
  int n;
};

int tactless_encoding_parse(const unsigned char *s, size_t n,
                            struct tactless_encoding *e);
void tactless_encoding_dump(const struct tactless_encoding *e);
void tactless_encoding_free(struct tactless_encoding *e);

unsigned char *tactless_readfile(const char *filename, size_t *size);

#endif
