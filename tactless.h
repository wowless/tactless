#ifndef __TACTLESS_H__
#define __TACTLESS_H__

struct tactless;
typedef struct tactless tactless;

tactless *tactless_open();
void tactless_close(tactless *t);
void tactless_dump(const tactless *t);

#endif
