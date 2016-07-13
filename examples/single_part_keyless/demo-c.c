#include <stdio.h>
#include <string.h>
#include "sodium.h"

#define MESSAGE ((const unsigned char *) "Arbitrary data to hash")
#define MESSAGE_LEN 22

int main () {
   unsigned char hash[crypto_generichash_BYTES];

   printf ("text: %s\n", MESSAGE);
   crypto_generichash(hash, sizeof hash,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   printf ("hash: %s (%d)\n", hash, strlen (hash));
   return 0;
}
