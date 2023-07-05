#include <stdlib.h>
#include "curl/curl.h"
#include "tactless.h"

struct tactless {
  CURL *curl;
};

tactless *tactless_open() {
  CURL *curl = curl_easy_init();
  if (!curl) {
    return NULL;
  }
  tactless *t = malloc(sizeof(*t));
  if (!t) {
    return NULL;
  }
  t->curl = curl;
  return t;
}

void tactless_close(tactless *t) {
  curl_easy_cleanup(t->curl);
  free(t);
}
