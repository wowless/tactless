#include "tactless.h"

#include <curl/curl.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>

struct collect_buffer {
  char *data;
  size_t size;
  size_t received;
};

static size_t collect_header_callback(char *data, size_t size, size_t nitems,
                                      void *cbarg) {
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
    buffer->data = malloc(length + 1);
    if (!buffer->data) {
      return 0;
    }
    buffer->data[length] = '\0';
    buffer->size = length;
  }
  return realsize;
}

static size_t collect_callback(void *data, size_t size, size_t nmemb,
                               void *cbarg) {
  size_t realsize = size * nmemb;
  struct collect_buffer *buffer = cbarg;
  if (!buffer->data || buffer->received + realsize > buffer->size) {
    return 0;
  }
  memcpy(buffer->data + buffer->received, data, realsize);
  buffer->received += realsize;
  return realsize;
}

static char *download(CURL *curl, const char *url, size_t *size) {
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

struct cdns {
  char host[128];
  char path[64];
};

static int parse_cdns(const char *s, struct cdns *cdns) {
  s = strstr(s, "\nus|");
  if (!s) {
    return 0;
  }
  s = s + 4;
  const char *p = strchr(s, '|');
  if (!p || p - s >= sizeof(cdns->path)) {
    return 0;
  }
  memcpy(cdns->path, s, p - s);
  cdns->path[p - s] = '\0';
  s = p + 1;
  p = strchr(s, ' ');
  if (!p || p - s >= sizeof(cdns->host)) {
    return 0;
  }
  memcpy(cdns->host, s, p - s);
  cdns->host[p - s] = '\0';
  return 1;
}

static int download_cdns(CURL *curl, struct cdns *cdns) {
  size_t size;
  char *text =
      download(curl, "http://us.patch.battle.net:1119/wow/cdns", &size);
  if (!text) {
    return 0;
  }
  int ret = parse_cdns(text, cdns);
  free(text);
  return ret;
}

struct versions {
  char build_config[33];
  char cdn_config[33];
};

static int parse_versions(const char *s, struct versions *versions) {
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

static int download_versions(CURL *curl, struct versions *versions) {
  size_t size;
  char *text =
      download(curl, "http://us.patch.battle.net:1119/wow/versions", &size);
  if (!text) {
    return 0;
  }
  int ret = parse_versions(text, versions);
  free(text);
  return ret;
}

static char *download_from_cdn(CURL *curl, const struct cdns *cdns,
                               const char *kind, const char *hash,
                               size_t *size) {
  char url[256];
  if (snprintf(url, 256, "http://%s/%s/%s/%c%c/%c%c/%s", cdns->host, cdns->path,
               kind, hash[0], hash[1], hash[2], hash[3], hash) >= 256) {
    return 0;
  }
  char *text = download(curl, url, size);
  if (!text) {
    return 0;
  }
  char digest[MD5_DIGEST_LENGTH];
  MD5(text, *size, digest);
  char dighex[MD5_DIGEST_LENGTH * 2];
  for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
    sprintf(dighex + i * 2, "%02x", digest[i]);
  }
  if (memcmp(hash, dighex, sizeof(dighex))) {
    return 0;
  }
  return text;
}

struct build_config {
  char root_ckey[33];
  char encoding_ckey[33];
  char encoding_ekey[33];
};

static int parse_hash(const char *s, char delim, char *hash) {
  const char *end = strchr(s, delim);
  if (end - s != 32) {
    return 0;
  }
  memcpy(hash, s, 32);
  hash[32] = '\0';
  return 1;
}

static int parse_build_config(const char *s,
                              struct build_config *build_config) {
  s = strstr(s, "\nroot = ");
  if (!s) {
    return 0;
  }
  s += 8;
  if (!parse_hash(s, '\n', build_config->root_ckey)) {
    return 0;
  }
  s = strstr(s + 32, "\nencoding = ");
  if (!s) {
    return 0;
  }
  s += 12;
  if (!parse_hash(s, ' ', build_config->encoding_ckey)) {
    return 0;
  }
  s += 33;
  return parse_hash(s, '\n', build_config->encoding_ekey);
}

static int download_build_config(CURL *curl, const struct cdns *cdns,
                                 const char *hash,
                                 struct build_config *build_config) {
  size_t size;
  char *text = download_from_cdn(curl, cdns, "config", hash, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_build_config(text, build_config);
  free(text);
  return ret;
}

struct cdn_config {
  char **archives;
  int narchives;
};

static int parse_cdn_config(const char *s, struct cdn_config *cdn_config) {
  cdn_config->narchives = 0;
  return 1;
}

static int download_cdn_config(CURL *curl, const struct cdns *cdns,
                               const char *hash,
                               struct cdn_config *cdn_config) {
  size_t size;
  char *text = download_from_cdn(curl, cdns, "config", hash, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_cdn_config(text, cdn_config);
  free(text);
  return ret;
}

struct tactless {
  CURL *curl;
  struct cdns cdns;
  struct versions versions;
  struct build_config build_config;
  struct cdn_config cdn_config;
};

tactless *tactless_open() {
  CURL *curl = curl_easy_init();
  if (!curl) {
    return NULL;
  }
  tactless *t = malloc(sizeof(*t));
  if (!t) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  t->cdn_config.archives = NULL;
  t->curl = curl;
  if (!download_cdns(curl, &t->cdns)) {
    tactless_close(t);
    return NULL;
  }
  if (!download_versions(curl, &t->versions)) {
    tactless_close(t);
    return NULL;
  }
  if (!download_build_config(curl, &t->cdns, t->versions.build_config,
                             &t->build_config)) {
    tactless_close(t);
    return NULL;
  }
  if (!download_cdn_config(curl, &t->cdns, t->versions.cdn_config,
                           &t->cdn_config)) {
    tactless_close(t);
    return NULL;
  }
  return t;
}

void tactless_dump(const tactless *t) {
  printf("cdns host = %s\n", t->cdns.host);
  printf("cdns path = %s\n", t->cdns.path);
  printf("version build config = %s\n", t->versions.build_config);
  printf("version cdn config = %s\n", t->versions.cdn_config);
  printf("root ckey = %s\n", t->build_config.root_ckey);
  printf("encoding ckey = %s\n", t->build_config.encoding_ckey);
  printf("encoding ekey = %s\n", t->build_config.encoding_ekey);
}

void tactless_close(tactless *t) {
  free(t->cdn_config.archives);
  curl_easy_cleanup(t->curl);
  free(t);
}
