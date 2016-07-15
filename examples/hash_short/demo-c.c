#include <stdio.h>
#include "sodium.h"

#define SHORT_DATA ((const unsigned char *) "Sparkling water")
#define SHORT_DATA_LEN 15

int main () {
   unsigned char hash[crypto_generichash_BYTES + 1] = {0};
   unsigned char key[crypto_generichash_KEYBYTES] = "123456789 123456";

   if (sodium_init() != 0) {
      return -1;
   }

   printf ("text: %s\n", SHORT_DATA);
   crypto_shorthash(hash, SHORT_DATA, SHORT_DATA_LEN, key);
   printf ("hash: %s\n", hash);
   return 0;
}
