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

   if (sodium_init() != 0) {
      return -1;
   }

   size_t min_hex_maxlen = crypto_generichash_BYTES_MIN * 2 + 1;
   size_t std_hex_maxlen = crypto_generichash_BYTES * 2 + 1;
   size_t max_hex_maxlen = crypto_generichash_BYTES_MAX * 2 + 1;
   unsigned char min_hex[min_hex_maxlen];
   unsigned char std_hex[std_hex_maxlen];
   unsigned char max_hex[max_hex_maxlen];

   printf ("text: %s\n", MESSAGE);
   crypto_generichash(minhash, crypto_generichash_BYTES_MIN,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   sodium_bin2hex (min_hex, min_hex_maxlen, minhash, crypto_generichash_BYTES_MIN);
   printf ("min hash: %s\n", min_hex);
   printf ("hash length is %d\n", strlen (minhash));

   crypto_generichash(hash, crypto_generichash_BYTES,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   sodium_bin2hex (std_hex, std_hex_maxlen, hash, crypto_generichash_BYTES);
   printf ("\nstd hash: %s\n", std_hex);
   printf ("hash length is %d\n", strlen (hash));

   crypto_generichash(maxhash, crypto_generichash_BYTES_MAX,
                      MESSAGE, MESSAGE_LEN,
                      NULL, 0);
   sodium_bin2hex (max_hex, max_hex_maxlen, maxhash, crypto_generichash_BYTES_MAX);
   printf ("\nmax hash: %s\n", max_hex);
   printf ("hash length is %d\n", strlen (maxhash));

   crypto_generichash(minhash, crypto_generichash_BYTES_MIN,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   sodium_bin2hex (min_hex, min_hex_maxlen, minhash, crypto_generichash_BYTES_MIN);
   printf ("\nkeyed min hash: %s\n", min_hex);

   crypto_generichash(hash, crypto_generichash_BYTES,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   sodium_bin2hex (std_hex, std_hex_maxlen, hash, crypto_generichash_BYTES);
   printf ("keyed std hash: %s\n", std_hex);

   crypto_generichash(maxhash, crypto_generichash_BYTES_MAX,
                      MESSAGE, MESSAGE_LEN,
                      key, sizeof key);
   sodium_bin2hex (max_hex, max_hex_maxlen, maxhash, crypto_generichash_BYTES_MAX);
   printf ("keyed max hash: %s\n", max_hex);
   return 0;
}
