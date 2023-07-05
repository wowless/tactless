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

struct versions {
  char build_config[33];
  char cdn_config[33];
};

int parse_versions(const char *s, struct versions *versions) {
  s = strstr(s, "\nus|");
  if (!s) {
    return 0;
  }
  s = s + 4;
  const char *p = strchr(s, '|');
  if (!p || p - s != 32) {
    return 0;
  }
  memcpy(versions->build_config, s, 32);
  versions->build_config[32] = '\0';
  s = p + 1;
  p = strchr(s, '|');
  if (!p || p - s != 32) {
    return 0;
  }
  memcpy(versions->cdn_config, s, 32);
  versions->cdn_config[32] = '\0';
  return 1;
}

int download_versions(CURL *curl, struct versions *versions) {
  size_t size;
  char *text = download(curl, "http://us.patch.battle.net:1119/wow/versions", &size);
  if (!text) {
    return 0;
  }
  int ret = parse_versions(text, versions);
  free(text);
  return ret;
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
  struct versions versions;
  if (!download_versions(curl, &versions)) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  printf("%s %s\n", versions.build_config, versions.cdn_config);
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
