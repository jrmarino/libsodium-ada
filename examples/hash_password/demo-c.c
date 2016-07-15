#include <stdio.h>
#include <string.h>
#include "sodium.h"

#define PASSWORD "Correct Horse Battery Staple"
#define KEY_LEN crypto_box_SEEDBYTES

int main () {
   unsigned char salt[crypto_pwhash_SALTBYTES] = "123456789+123456";
   unsigned char key[KEY_LEN + 1] = {0};

   if (crypto_pwhash
    (key, KEY_LEN, PASSWORD, strlen(PASSWORD), salt,
     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
       /* out of memory */
       return -1;
    }

   printf ("password: %s\n", PASSWORD);
   printf ("pass key: %s\n", key);
   return 0;
}
