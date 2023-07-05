#include <stdlib.h>
#include <string.h>
#include "curl/curl.h"
#include "tactless.h"

struct tactless {
  CURL *curl;
};

struct collect_buffer {
  char *data;
  size_t size;
};

static size_t collect_callback(void *data, size_t size, size_t nmemb, void *cbarg) {
  size_t realsize = size * nmemb;
  struct collect_buffer *buffer = cbarg;
  char *p = realloc(buffer->data, buffer->size + realsize);
  if (!p) {
    return 0;
  }
  memcpy(p + buffer->size, data, realsize);
  buffer->data = p;
  buffer->size += realsize;
  return realsize;
}

char *download(CURL *curl, const char *url, size_t *size) {
  struct collect_buffer buffer = {
    .data = NULL,
    .size = 0,
  };
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  CURLcode code = curl_easy_perform(curl);
  if (code != CURLE_OK) {
    free(buffer.data);
    return NULL;
  }
  *size = buffer.size;
  return buffer.data;
}

tactless *tactless_open() {
  CURL *curl = curl_easy_init();
  if (!curl) {
    return NULL;
  }
  size_t cdns_size;
  char *cdns = download(curl, "http://us.patch.battle.net:1119/wow/cdns", &cdns_size);
  if (!cdns) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  fwrite(cdns, cdns_size, 1, stdout);
  free(cdns);
  tactless *t = malloc(sizeof(*t));
  if (!t) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  t->curl = curl;
  return t;
}

void tactless_close(tactless *t) {
  curl_easy_cleanup(t->curl);
  free(t);
}
