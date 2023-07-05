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
  size_t received;
};

static size_t collect_header_callback(char *data, size_t size, size_t nitems, void *cbarg) {
  size_t realsize = size * nitems;
  if (realsize >= 16 && !memcmp(data, "Content-Length: ", 16)) {
    memcpy(data, data + 16, realsize - 16);
    data[realsize - 16] = '\0';
    long length = atol(data);
    if (length == 0) {
      return 0;
    }
    struct collect_buffer *buffer = cbarg;
    if (buffer->data) {
      return 0;
    }
    buffer->data = malloc(length);
    if (!buffer->data) {
      return 0;
    }
    buffer->size = length;
  }
  return realsize;
}

static size_t collect_callback(void *data, size_t size, size_t nmemb, void *cbarg) {
  size_t realsize = size * nmemb;
  struct collect_buffer *buffer = cbarg;
  if (!buffer->data || buffer->received + realsize > buffer->size) {
    return 0;
  }
  memcpy(buffer->data + buffer->received, data, realsize);
  buffer->received += realsize;
  return realsize;
}

char *download(CURL *curl, const char *url, size_t *size) {
  struct collect_buffer buffer;
  bzero(&buffer, sizeof(buffer));
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, collect_header_callback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  CURLcode code = curl_easy_perform(curl);
  if (code != CURLE_OK) {
    free(buffer.data);
    return NULL;
  }
  *size = buffer.received;
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
  size_t versions_size;
  char *versions = download(curl, "http://us.patch.battle.net:1119/wow/versions", &versions_size);
  if (!versions) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  fwrite(versions, versions_size, 1, stdout);
  free(versions);
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
