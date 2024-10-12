#include "tactless.h"

#include <curl/curl.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

typedef unsigned char byte;

struct collect_buffer {
  byte *data;
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

static byte *download(CURL *curl, const char *url, size_t *size) {
  struct collect_buffer buffer;
  memset(&buffer, 0, sizeof(buffer));
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

static int download_cdns(CURL *curl, const char *product, struct cdns *cdns) {
  size_t size;
  char url[128];
  if (snprintf(url, sizeof(url), "http://us.patch.battle.net:1119/%s/cdns",
               product) >= sizeof(url)) {
    return 0;
  }
  byte *text = download(curl, url, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_cdns((char *)text, cdns);
  free(text);
  return ret;
}

static int parse_hash(const char *s, char delim, byte *hash) {
  const char *end = strchr(s, delim);
  if (end - s != 32) {
    return 0;
  }
  unsigned int x;
  for (; s != end; s += 2, ++hash) {
    if (sscanf(s, "%02x", &x) != 1) {
      return 0;
    }
    *hash = x;
  }
  return 1;
}

struct versions {
  byte build_config[16];
  byte cdn_config[16];
};

static int parse_versions(const char *s, struct versions *versions) {
  s = strstr(s, "\nus|");
  if (!s) {
    return 0;
  }
  if (!parse_hash(s + 4, '|', versions->build_config)) {
    return 0;
  }
  if (!parse_hash(s + 37, '|', versions->cdn_config)) {
    return 0;
  }
  return 1;
}

static int download_versions(CURL *curl, const char *product,
                             struct versions *versions) {
  size_t size;
  char url[128];
  if (snprintf(url, sizeof(url), "http://us.patch.battle.net:1119/%s/versions",
               product) >= sizeof(url)) {
    return 0;
  }
  byte *text = download(curl, url, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_versions((char *)text, versions);
  free(text);
  return ret;
}

byte *tactless_readfile(const char *filename, size_t *size) {
  FILE *f = fopen(filename, "r");
  if (!f) {
    return 0;
  }
  struct stat stat;
  /* NOLINTNEXTLINE(clang-diagnostic-deprecated-declarations) */
  if (fstat(fileno(f), &stat) != 0) {
    fclose(f);
    return 0;
  }
  *size = stat.st_size;
  byte *text = malloc(*size + 1);
  if (!text) {
    fclose(f);
    return 0;
  }
  text[*size] = '\0';
  if (fread(text, *size, 1, f) != 1) {
    free(text);
    fclose(f);
    return 0;
  }
  if (fclose(f) != 0) {
    free(text);
    return 0;
  }
  return text;
}

static int writeall(const char *filename, const byte *text, size_t size) {
  FILE *f = fopen(filename, "w");
  if (!f) {
    return 0;
  }
  if (fwrite(text, size, 1, f) != 1) {
    fclose(f);
    return 0;
  }
  if (fclose(f) != 0) {
    return 0;
  }
  return 1;
}

static uint16_t uint16be(const byte *s) { return s[1] | s[0] << 8; }

static uint32_t uint24be(const byte *s) {
  return s[2] | s[1] << 8 | s[0] << 16;
}

static uint32_t uint32be(const byte *s) {
  return s[3] | s[2] << 8 | s[1] << 16 | s[0] << 24;
}

static uint32_t uint32le(const byte *s) {
  return s[0] | s[1] << 8 | s[2] << 16 | s[3] << 24;
}

static void md5sum(const byte *s, size_t size, byte *digest) {
  MD5(s, size, digest); /* NOLINT(clang-diagnostic-deprecated-declarations) */
}

static int md5check(const byte *s, size_t size, const byte *md5) {
  byte digest[16];
  md5sum(s, size, digest);
  return memcmp(digest, md5, 16) == 0;
}

static byte *parse_blte(const byte *s, size_t size, const byte *ekey,
                        size_t *out_size) {
  if (size < 8) {
    return 0;
  }
  if (memcmp(s, "BLTE", 4) != 0) {
    return 0;
  }
  uint32_t header_size = uint32be(s + 4);
  if (size < header_size) {
    return 0;
  }
  /* TODO support header_size == 0 */
  if (header_size == 0) {
    return 0;
  }
  if (header_size < 12) {
    return 0;
  }
  if (!md5check(s, header_size, ekey)) {
    return 0;
  }
  uint8_t flags = s[8];
  uint32_t num_chunks = uint24be(s + 9);
  if (flags != 0xf || num_chunks == 0 || num_chunks * 24 + 12 != header_size) {
    return 0;
  }
  const byte *data = s + header_size;
  const byte *end = s + size;
  *out_size = 0;
  for (const byte *entry = s + 12; entry != s + header_size; entry += 24) {
    uint32_t compressed_size = uint32be(entry);
    uint32_t uncompressed_size = uint32be(entry + 4);
    if (end - data < compressed_size) {
      return 0;
    }
    if (!md5check(data, compressed_size, entry + 8)) {
      return 0;
    }
    data += compressed_size;
    *out_size += uncompressed_size;
  }
  if (data != end) {
    return 0;
  }
  if (!*out_size) {
    return 0;
  }
  byte *out = malloc(*out_size);
  if (!out) {
    return 0;
  }
  byte *cursor = out;
  data = s + header_size;
  for (const byte *entry = s + 12; entry != s + header_size; entry += 24) {
    uint32_t compressed_size = uint32be(entry);
    uint32_t uncompressed_size = uint32be(entry + 4);
    uLongf zsize = uncompressed_size;
    switch (data[0]) {
      case 'N':
        memcpy(cursor, data + 1, compressed_size - 1);
        break;
      case 'Z':
        if (uncompress(cursor, &zsize, data + 1, compressed_size - 1) != Z_OK) {
          free(out);
          return 0;
        }
        if (zsize != uncompressed_size) {
          free(out);
          return 0;
        }
        break;
      default:
        free(out);
        return 0;
    }
    data += compressed_size;
    cursor += uncompressed_size;
  }
  return out;
}

static void hash2hex(const byte *hash, char *hex) {
  for (const byte *end = hash + 16; hash != end; ++hash, hex += 2) {
    sprintf(hex, "%02x", *hash);
  }
}

static int mkurl(char *url, size_t size, const struct cdns *cdns,
                 const char *kind, const char *hex, const char *suffix) {
  return snprintf(url, size, "http://%s/%s/%s/%c%c/%c%c/%s%s", cdns->host,
                  cdns->path, kind, hex[0], hex[1], hex[2], hex[3], hex,
                  suffix) < size;
}

static byte *download_from_cdn(CURL *curl, const struct cdns *cdns,
                               const char *kind, const byte *ckey,
                               const byte *ekey, size_t *size) {
  char hex[33];
  hash2hex(ckey, hex);
  char filename[39];
  sprintf(filename, "cache/%s", hex);
  byte *text = tactless_readfile(filename, size);
  if (text && md5check(text, *size, ckey)) {
    return text;
  }
  free(text);
  if (ekey) {
    hash2hex(ekey, hex);
  }
  char url[256];
  if (!mkurl(url, sizeof(url), cdns, kind, hex, "")) {
    return 0;
  }
  text = download(curl, url, size);
  if (!text) {
    return 0;
  }
  if (ekey) {
    byte *t = parse_blte(text, *size, ekey, size);
    free(text);
    if (!t) {
      return 0;
    }
    text = t;
  }
  if (!md5check(text, *size, ckey)) {
    free(text);
    return 0;
  }
  if (!writeall(filename, text, *size)) {
    free(text);
    return 0;
  }
  return text;
}

struct build_config {
  byte root_ckey[16];
  byte encoding_ckey[16];
  byte encoding_ekey[16];
  byte install_ckey[16];
  byte install_ekey[16];
};

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
  s = strstr(s + 32, "\ninstall = ");
  if (!s) {
    return 0;
  }
  s += 11;
  if (!parse_hash(s, ' ', build_config->install_ckey)) {
    return 0;
  }
  s += 33;
  if (!parse_hash(s, '\n', build_config->install_ekey)) {
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
  if (!parse_hash(s, '\n', build_config->encoding_ekey)) {
    return 0;
  }
  return 1;
}

static int download_build_config(CURL *curl, const struct cdns *cdns,
                                 const byte *hash,
                                 struct build_config *build_config) {
  size_t size;
  byte *text = download_from_cdn(curl, cdns, "config", hash, 0, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_build_config((char *)text, build_config);
  free(text);
  return ret;
}

struct cdn_config {
  byte (*archives)[16];
  int narchives;
};

static int parse_cdn_config(const char *s, struct cdn_config *cdn_config) {
  s = strstr(s, "\narchives = ");
  if (!s) {
    return 0;
  }
  s += 12;
  const char *p = strchr(s, '\n');
  if (!p) {
    return 0;
  }
  ++p;
  if ((p - s) % 33 != 0) {
    return 0;
  }
  size_t nn = (p - s) / 33;
  if (nn > INT_MAX) {
    return 0;
  }
  int n = (int)nn;
  byte(*a)[16] = malloc(sizeof(byte[16]) * n);
  if (!a) {
    return 0;
  }
  for (int i = 0; i < n - 1; ++i) {
    if (!parse_hash(s, ' ', a[i])) {
      free(a);
      return 0;
    }
    s += 33;
  }
  if (!parse_hash(s, '\n', a[n - 1])) {
    free(a);
    return 0;
  }
  cdn_config->narchives = n;
  cdn_config->archives = a;
  return 1;
}

static int download_cdn_config(CURL *curl, const struct cdns *cdns,
                               const byte *hash,
                               struct cdn_config *cdn_config) {
  size_t size;
  byte *text = download_from_cdn(curl, cdns, "config", hash, 0, &size);
  if (!text) {
    return 0;
  }
  int ret = parse_cdn_config((char *)text, cdn_config);
  free(text);
  return ret;
}

int tactless_archive_index_parse(const byte *s, size_t n,
                                 struct tactless_archive_index *a) {
  if (n < 28) {
    /* footer too small */
    return 0;
  }
  if ((n - 28) % (4096 + 24) != 0) {
    /* has an incomplete block */
    return 0;
  }
  size_t nb = (n - 28) / (4096 + 24);
  const byte *footer = s + n - 28;
  const byte *bhashes = footer - nb * 8;
  const byte *lasts = bhashes - nb * 16;
  byte digest[16];
  md5sum(lasts, nb * 24, digest);
  if (memcmp(digest, footer, 8) != 0) {
    /* toc checksum mismatch */
    return 0;
  }
  /*
   * The footer internal hash is computed on the last 20 bytes, but with the
   * last 8 bytes of that zeroed out. Obviously.
   */
  byte footcomp[20];
  memcpy(footcomp, footer + 8, 12);
  memset(footcomp + 12, 0, 8);
  md5sum(footcomp, 20, digest);
  if (memcmp(digest, footer + 20, 8) != 0) {
    /* internal footer checksum */
    return 0;
  }
  if (footer[8] != 1) {
    /* version mismatch */
    return 0;
  }
  if (footer[9] != 0 || footer[10] != 0) {
    /* unknown fields mismatch */
    return 0;
  }
  if (footer[11] != 4) {
    /* block size mismatch */
    return 0;
  }
  if (footer[12] != 4) {
    /* offset bytes mismatch */
    return 0;
  }
  if (footer[13] != 4) {
    /* size bytes mismatch */
    return 0;
  }
  if (footer[14] != 16) {
    /* key size mismatch */
    return 0;
  }
  if (footer[15] != 8) {
    /* checksum size mismatch */
    return 0;
  }
  for (const byte *b = s, *h = bhashes; b != lasts; b += 4096, h += 8) {
    md5sum(b, 4096, digest);
    if (memcmp(digest, h, 8) != 0) {
      return 0;
    }
  }
  size_t ec = 0;
  for (const byte *b = s, *e = lasts; b != lasts; b += 4096, e += 16) {
    const byte *be = b + 4096 - 24;
    int found = 0;
    for (const byte *c = b; c <= be && !found; c += 24, ++ec) {
      found = memcmp(c, e, 16) == 0;
    }
    if (!found) {
      return 0;
    }
  }
  if (ec == 0 || ec != uint32le(footer + 16)) {
    return 0;
  }
  byte *data = malloc(ec * 24);
  if (!data) {
    return 0;
  }
  byte *p = data;
  for (const byte *b = s, *e = lasts; b != lasts; b += 4096, e += 16) {
    const byte *c = b;
    for (int found = 0; !found; c += 24) {
      found = memcmp(c, e, 16) == 0;
    }
    memcpy(p, b, c - b);
    p += c - b;
  }
  md5sum(footer, 28, a->name);
  a->data = data;
  a->n = ec;
  return 1;
}

void tactless_archive_index_dump(const struct tactless_archive_index *a) {
  char hex[33];
  hash2hex(a->name, hex);
  printf("name = %s\n", hex);
  printf("num elements = %zu\n", a->n);
  const byte *end = a->data + a->n * 24;
  for (const byte *p = a->data; p < end; p += 24) {
    hash2hex(p, hex);
    printf("%s %10u %10u\n", hex, uint32be(p + 16), uint32be(p + 20));
  }
}

void tactless_archive_index_free(struct tactless_archive_index *a) {
  free(a->data);
}

struct multi_collect {
  struct collect_buffer buffer;
  CURL *curl;
};

static int download_archive_index_multi(const struct cdns *cdns,
                                        const struct cdn_config *cdn_config,
                                        struct multi_collect *c, CURLM *multi) {
  int n = cdn_config->narchives;
  curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 64);
  char url[256];
  char hex[33];
  for (int i = 0; i < n; ++i) {
    hash2hex(cdn_config->archives[i], hex);
    if (!mkurl(url, sizeof(url), cdns, "data", hex, ".index")) {
      return 0;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
      return 0;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, collect_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &c[i].buffer);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &c[i].buffer);
    curl_multi_add_handle(multi, curl);
    c[i].curl = curl;
  }
  for (int nn = n; nn;) {
    if (curl_multi_perform(multi, &nn) != CURLM_OK) {
      return 0;
    }
    if (nn && curl_multi_poll(multi, 0, 0, 100, 0) != CURLM_OK) {
      return 0;
    }
  }
  for (int i = 0; i < n; ++i) {
    int rem;
    CURLMsg *msg = curl_multi_info_read(multi, &rem);
    if (msg->msg != CURLMSG_DONE || msg->data.result != CURLE_OK ||
        rem != n - i - 1) {
      return 0;
    }
    char filename[45];
    hash2hex(cdn_config->archives[i], hex);
    sprintf(filename, "cache/%s.index", hex);
    if (!writeall(filename, c[i].buffer.data, c[i].buffer.size)) {
      return 0;
    }
  }
  return 1;
}

static int download_archive_index(const struct cdns *cdns,
                                  const struct cdn_config *cdn_config) {
  int n = cdn_config->narchives;
  struct multi_collect *c = calloc(n, sizeof(*c));
  CURLM *m = curl_multi_init();
  int ret = c && m && download_archive_index_multi(cdns, cdn_config, c, m);
  if (c) {
    for (int i = 0; i < n; ++i) {
      curl_multi_remove_handle(m, c[i].curl);
      curl_easy_cleanup(c[i].curl);
      free(c[i].buffer.data);
    }
  }
  free(c);
  curl_multi_cleanup(m);
  return ret;
}

static int download_install(CURL *curl, const struct cdns *cdns,
                            const byte *ckey, const byte *ekey) {
  size_t size;
  byte *text = download_from_cdn(curl, cdns, "data", ckey, ekey, &size);
  int ret = text != NULL;
  free(text);
  return ret;
}

int tactless_encoding_parse(const byte *s, size_t n,
                            struct tactless_encoding *e) {
  if (n < 22) {
    /* header too small */
    return 0;
  }
  if (s[0] != 'E' || s[1] != 'N') {
    /* bad signature */
    return 0;
  }
  if (s[2] != 1) {
    /* bad version */
    return 0;
  }
  if (s[3] != 16 || s[4] != 16) {
    /* unexpected hash sizes */
    return 0;
  }
  if (uint16be(s + 5) != 4 || uint16be(s + 7) != 4) {
    /* unexpected page sizes */
    return 0;
  }
  uint32_t cekey_page_count = uint32be(s + 9);
  uint32_t espec_page_count = uint32be(s + 13);
  if (s[17] != 0) {
    /* unexpected unknown byte value */
    return 0;
  }
  uint32_t espec_block_size = uint32be(s + 18);
  if (n <
      22 + (cekey_page_count + espec_page_count) * 4128 + espec_block_size) {
    /* wrong size */
    return 0;
  }
  const byte *index = s + 22 + espec_block_size;
  const byte *data = index + (size_t)32 * cekey_page_count;
  int entries = 0;
  for (const byte *ic = index, *dc = data; ic != data; ic += 32, dc += 4096) {
    if (!md5check(dc, 4096, ic + 16)) {
      return 0;
    }
    const byte *ec = dc;
    const byte *end = dc + 4096;
    while (ec < end && *ec) {
      int sz = 22 + 16 * *ec;
      if (ec + sz > end) {
        return 0;
      }
      ++entries;
      ec += sz;
    }
  }
  if (!entries) {
    return 0;
  }
  byte *arr = malloc(entries * (size_t)32);
  if (!arr) {
    return 0;
  }
  byte *ac = arr;
  for (const byte *ic = index, *dc = data; ic != data; ic += 32, dc += 4096) {
    const byte *ec = dc;
    const byte *end = dc + 4096;
    while (ec < end && *ec) {
      memcpy(ac, ec + 6, 32);
      ac += 32;
      ec += 22 + 16 * *ec;
    }
  }
  e->data = arr;
  e->n = entries;
  return 1;
}

void tactless_encoding_dump(const struct tactless_encoding *e) {
  char buf[66];
  const byte *end = e->data + e->n * (size_t)32;
  for (const byte *p = e->data; p != end; p += 32) {
    hash2hex(p, buf);
    buf[32] = ' ';
    hash2hex(p + 16, buf + 33);
    buf[65] = '\n';
    fwrite(buf, 66, 1, stdout);
  }
}

void tactless_encoding_free(struct tactless_encoding *e) { free(e->data); }

static int download_encoding(CURL *curl, const struct cdns *cdns,
                             const byte *ckey, const byte *ekey,
                             struct tactless_encoding *e) {
  size_t size;
  byte *text = download_from_cdn(curl, cdns, "data", ckey, ekey, &size);
  if (!text) {
    return 0;
  }
  int ret = tactless_encoding_parse(text, size, e);
  free(text);
  return ret;
}

static int encoding_cmp(const void *key, const void *mem) {
  const char *k = key;
  const char *m = mem;
  return memcmp(k, m, 16);
}

static const byte *ckey2ekey(const struct tactless_encoding *e,
                             const byte *ckey) {
  const byte *p = bsearch(ckey, e->data, e->n, 32, encoding_cmp);
  return p ? p + 16 : 0;
}

static int parse_root_legacy(const byte *s, size_t size,
                             struct tactless_root *root) {
  const byte *end = s + size;
  uint32_t num_files = 0;
  while (s != end) {
    if (end - s < 12) {
      return 0;
    }
    uint32_t num_records = uint32le(s);
    size_t bsz = 12 + 28 * num_records;
    if (end - s < bsz) {
      return 0;
    }
    s += bsz;
    num_files += num_records;
  }
  root->total_file_count = num_files;
  root->named_file_count = num_files;
  return 1;
}

static int parse_root_mfst(const byte *s, size_t size,
                           struct tactless_root *root) {
  if (size < 12) {
    return 0;
  }
  const byte *end = s + size;
  uint32_t total_file_count = uint32le(s + 4);
  uint32_t named_file_count = uint32le(s + 8);
  if (total_file_count == 24 && named_file_count == 1) {
    if (size < 24) {
      return 0;
    }
    /* Treat this as having the new-style header. */
    total_file_count = uint32le(s + 12);
    named_file_count = uint32le(s + 16);
    s += 24;
  } else {
    s += 12;
  }
  uint32_t total_files = 0;
  uint32_t named_files = 0;
  while (s != end) {
    if (end - s < 12) {
      return 0;
    }
    uint32_t num_records = uint32le(s);
    uint32_t flags = uint32le(s + 4);
    size_t rsz = 20 + ((flags & 0x10000000) ? 0 : 8);
    size_t bsz = 12 + rsz * num_records;
    if (end - s < bsz) {
      return 0;
    }
    s += bsz;
    total_files += num_records;
    named_files += (flags & 0x10000000) ? 0 : num_records;
  }
  if (total_files != total_file_count || named_files != named_file_count) {
    return 0;
  }
  root->total_file_count = total_file_count;
  root->named_file_count = named_file_count;
  return 1;
}

int tactless_root_parse(const byte *s, size_t size,
                        struct tactless_root *root) {
  if (size < 4) {
    return 0;
  }
  if (memcmp(s, "TSFM", 4) != 0) {
    return parse_root_legacy(s, size, root);
  } else {
    return parse_root_mfst(s, size, root);
  }
}

void tactless_root_dump(const struct tactless_root *root) {
  printf("total file count = %d\n", root->total_file_count);
  printf("named file count = %d\n", root->named_file_count);
}

void tactless_root_free(struct tactless_root *root) {}

static int download_root(CURL *curl, const struct cdns *cdns, const byte *ckey,
                         const byte *ekey, struct tactless_root *root) {
  size_t size;
  byte *text = download_from_cdn(curl, cdns, "data", ckey, ekey, &size);
  if (!text) {
    return 0;
  }
  int ret = tactless_root_parse(text, size, root);
  free(text);
  return ret;
}

struct tactless {
  CURL *curl;
  struct cdns cdns;
  struct versions versions;
  struct build_config build_config;
  struct cdn_config cdn_config;
  struct tactless_encoding encoding;
  struct tactless_root root;
};

static int tactless_init(struct tactless *t, const char *product) {
  CURL *curl = curl_easy_init();
  if (!curl) {
    return 0;
  }
  t->curl = curl;
  if (!download_cdns(curl, product, &t->cdns)) {
    return 0;
  }
  if (!download_versions(curl, product, &t->versions)) {
    return 0;
  }
  if (!download_build_config(curl, &t->cdns, t->versions.build_config,
                             &t->build_config)) {
    return 0;
  }
  if (!download_cdn_config(curl, &t->cdns, t->versions.cdn_config,
                           &t->cdn_config)) {
    return 0;
  }
  const struct build_config *b = &t->build_config;
  if (!download_install(curl, &t->cdns, b->install_ckey, b->install_ekey)) {
    return 0;
  }
  if (!download_encoding(curl, &t->cdns, b->encoding_ckey, b->encoding_ekey,
                         &t->encoding)) {
    return 0;
  }
  const byte *root_ekey = ckey2ekey(&t->encoding, b->root_ckey);
  if (!root_ekey) {
    return 0;
  }
  if (!download_root(curl, &t->cdns, b->root_ckey, root_ekey, &t->root)) {
    return 0;
  }
  if (!download_archive_index(&t->cdns, &t->cdn_config)) {
    return 0;
  }
  return 1;
}

struct tactless *tactless_open(const char *product) {
  struct tactless *t = calloc(1, sizeof(*t));
  if (!t) {
    return NULL;
  }
  if (!tactless_init(t, product)) {
    tactless_close(t);
    return NULL;
  }
  return t;
}

void tactless_dump(const struct tactless *t) {
  char hex[33];
  printf("cdns host = %s\n", t->cdns.host);
  printf("cdns path = %s\n", t->cdns.path);
  hash2hex(t->versions.build_config, hex);
  printf("version build config = %s\n", hex);
  hash2hex(t->versions.cdn_config, hex);
  printf("version cdn config = %s\n", hex);
  hash2hex(t->build_config.root_ckey, hex);
  printf("root ckey = %s\n", hex);
  hash2hex(t->build_config.encoding_ckey, hex);
  printf("encoding ckey = %s\n", hex);
  hash2hex(t->build_config.encoding_ekey, hex);
  printf("encoding ekey = %s\n", hex);
  hash2hex(t->build_config.install_ckey, hex);
  printf("install ckey = %s\n", hex);
  hash2hex(t->build_config.install_ekey, hex);
  printf("install ekey = %s\n", hex);
  printf("num archives = %d\n", t->cdn_config.narchives);
  const struct cdn_config *c = &t->cdn_config;
  if (c->narchives > 0) {
    hash2hex(c->archives[0], hex);
    printf("first archive = %s\n", hex);
    hash2hex(c->archives[c->narchives - 1], hex);
    printf("last archive = %s\n", hex);
  }
  printf("encoding entries = %d\n", t->encoding.n);
  if (t->encoding.n > 0) {
    hash2hex(t->encoding.data, hex);
    printf("first encoding ckey = %s\n", hex);
    hash2hex(t->encoding.data + 16, hex);
    printf("first encoding ekey = %s\n", hex);
  }
  const byte *root_ekey = ckey2ekey(&t->encoding, t->build_config.root_ckey);
  if (root_ekey) {
    hash2hex(root_ekey, hex);
    printf("root ekey = %s\n", hex);
  }
  printf("root total file count = %d\n", t->root.total_file_count);
  printf("root named file count = %d\n", t->root.named_file_count);
}

void tactless_close(struct tactless *t) {
  free(t->cdn_config.archives);
  tactless_encoding_free(&t->encoding);
  curl_easy_cleanup(t->curl);
  free(t);
}
