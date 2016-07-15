#include <stdio.h>
#include "sodium.h"

#define SHORT_DATA ((const unsigned char *) "Sparkling water")
#define SHORT_DATA_LEN 15

int main () {
   unsigned char hash[crypto_shorthash_BYTES + 1] = {0};
   unsigned char key[crypto_shorthash_KEYBYTES] = "123456789 123456";

   if (sodium_init() != 0) {
      return -1;
   }

   printf ("text: %s\n", SHORT_DATA);
   crypto_shorthash(hash, SHORT_DATA, SHORT_DATA_LEN, key);

   size_t hex_maxlen = crypto_shorthash_BYTES * 2 + 1;
   unsigned char hex[hex_maxlen];

   sodium_bin2hex (hex, hex_maxlen, hash, crypto_shorthash_BYTES);
   printf ("hash: %s\n", hex);
   return 0;
}
