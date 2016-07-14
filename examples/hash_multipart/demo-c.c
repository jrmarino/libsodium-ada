#include <stdio.h>
#include "sodium.h"

#define MESSAGE_PART1 ((const unsigned char *) "Arbitrary data to hash")
#define MESSAGE_PART1_LEN 22

#define MESSAGE_PART2 ((const unsigned char *) "is longer than expected")
#define MESSAGE_PART2_LEN 23

int main () {
   unsigned char hash[crypto_generichash_BYTES + 1] = {0};
   unsigned char key[crypto_generichash_KEYBYTES] = "123456789 123456789 123456789 12";
   crypto_generichash_state state;

   printf ("text 1: %s\ntext 2: %s\n", MESSAGE_PART1, MESSAGE_PART2);
   crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);
   crypto_generichash_update(&state, MESSAGE_PART1, MESSAGE_PART1_LEN);
   crypto_generichash_update(&state, MESSAGE_PART2, MESSAGE_PART2_LEN);
   crypto_generichash_final(&state, hash, crypto_generichash_BYTES);

   printf ("hash: %s\n", hash);
   crypto_generichash_init(&state, key, sizeof key, crypto_generichash_BYTES);
   crypto_generichash_update(&state, MESSAGE_PART1, MESSAGE_PART1_LEN);
   crypto_generichash_update(&state, MESSAGE_PART2, MESSAGE_PART2_LEN);
   crypto_generichash_final(&state, hash, crypto_generichash_BYTES);
   printf ("\nkeyed hash: %s\n", hash);
   printf ("size of state: %d\n", sizeof state);
   printf ("offset t %d\n", offsetof(crypto_generichash_state, t));
   printf ("offset f %d\n", offsetof(crypto_generichash_state, f));
   printf ("offset buf %d\n", offsetof(crypto_generichash_state, buf));
   printf ("offset buflen %d\n", offsetof(crypto_generichash_state, buflen));
   printf ("offset last_node %d\n", offsetof(crypto_generichash_state, last_node));
   return 0;
}
