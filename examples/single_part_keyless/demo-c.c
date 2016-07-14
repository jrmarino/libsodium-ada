#include <stdio.h>
#include <string.h>
#include "sodium.h"

#define MESSAGE ((const unsigned char *) "Arbitrary text to hash")
#define MESSAGE_LEN 22

int main () {
   unsigned char hash[crypto_generichash_BYTES + 1] = {0};
   unsigned char minhash[crypto_generichash_BYTES_MIN + 1] = {0};
   unsigned char maxhash[crypto_generichash_BYTES_MAX + 1] = {0};
   unsigned char key[crypto_generichash_KEYBYTES] = "123456789 123456789 123456789 12";

   printf ("text: %s\n", MESSAGE);
   crypto_generichash(hash, crypto_generichash_BYTES,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   printf ("hash: %s\n", hash);
   printf ("hash length is %d\n", strlen (hash));

   crypto_generichash(minhash, crypto_generichash_BYTES_MIN,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   printf ("%s\n", minhash);
   printf ("hash length is %d\n", strlen (minhash));

   crypto_generichash(maxhash, crypto_generichash_BYTES_MAX,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   printf ("%s\n", maxhash);
   printf ("hash length is %d\n", strlen (maxhash));

   crypto_generichash(hash, crypto_generichash_BYTES,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   printf ("\nkeyed std hash:\n%s\n", hash);

   crypto_generichash(minhash, crypto_generichash_BYTES_MIN,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   printf ("\nkeyed min hash:\n%s\n", minhash);

   crypto_generichash(maxhash, crypto_generichash_BYTES_MAX,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   printf ("\nkeyed max hash:\n%s\n", maxhash);
   return 0;
}
