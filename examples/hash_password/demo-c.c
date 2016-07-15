#include <stdio.h>
#include <string.h>
#include "sodium.h"

#define PASSWORD "Correct Horse Battery Staple"
#define KEY_LEN crypto_box_SEEDBYTES

int main () {
   unsigned char salt[crypto_pwhash_SALTBYTES] = "123456789+123456";
   unsigned char key[KEY_LEN + 1] = {0};

   if (sodium_init() != 0) {
      return -1;
   }

   if (crypto_pwhash
    (key, KEY_LEN, PASSWORD, strlen(PASSWORD), salt,
     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
       /* out of memory */
       return -1;
    }

   size_t hex_maxlen = KEY_LEN * 2 + 1;
   unsigned char hex[hex_maxlen];

   sodium_bin2hex (hex, hex_maxlen, key, KEY_LEN);

   printf ("password: %s\n", PASSWORD);
   printf ("pass key: %s\n", hex);

   char hashed_password[crypto_pwhash_STRBYTES + 1] = {0};

   if (crypto_pwhash_str
    (hashed_password, PASSWORD, strlen(PASSWORD),
     crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
       /* out of memory */
       return -1;
    }
   printf ("hash: %s\n", hashed_password);

   if (crypto_pwhash_str_verify
    (hashed_password, PASSWORD, strlen(PASSWORD)) == 0) {
       printf ("Hash verification passed\n");
   } else {
       printf ("Hash verification failed\n");
   }

   return 0;
}
