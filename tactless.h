#ifndef __TACTLESS_H__
#define __TACTLESS_H__

#include "tactless_export.h"

struct tactless;
typedef struct tactless tactless;

TACTLESS_EXPORT tactless *tactless_open(const char *product);
TACTLESS_EXPORT void tactless_close(tactless *t);
TACTLESS_EXPORT void tactless_dump(const tactless *t);

#endif
