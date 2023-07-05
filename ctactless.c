#include <stdio.h>
#include "curl/curl.h"

int main(int argc, char **argv) {
    CURL *curl = curl_easy_init();
    if (curl) {
      curl_easy_cleanup(curl);
    }
    puts("Hello, world!");
    return 0;
}
