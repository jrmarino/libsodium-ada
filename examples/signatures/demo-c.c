#include <stdio.h>
#include "sodium.h"

#define MESSAGE (const unsigned char *) "JRM wrote this note."
#define MESSAGE_LEN 20

int main () {
   unsigned char pk[crypto_sign_PUBLICKEYBYTES];
   unsigned char sk[crypto_sign_SECRETKEYBYTES];

   if (sodium_init() != 0) {
      return -1;
   }

   crypto_sign_keypair(pk, sk);

   unsigned char sig[crypto_sign_BYTES];
   crypto_sign_detached(sig, NULL, MESSAGE, MESSAGE_LEN, sk);

   size_t pk_maxlen = crypto_sign_PUBLICKEYBYTES * 2 + 1;
   size_t sk_maxlen = crypto_sign_SECRETKEYBYTES * 2 + 1;
   size_t sig_maxlen = crypto_sign_BYTES * 2 + 1;
   size_t seed_maxlen = crypto_sign_SEEDBYTES * 2 + 1;

   unsigned char pk_hex[pk_maxlen];
   unsigned char sk_hex[sk_maxlen];
   unsigned char sig_hex[sig_maxlen];
   unsigned char seed_hex[seed_maxlen];

   sodium_bin2hex (pk_hex, pk_maxlen, pk, crypto_sign_PUBLICKEYBYTES);
   sodium_bin2hex (sk_hex, sk_maxlen, sk, crypto_sign_SECRETKEYBYTES);
   sodium_bin2hex (sig_hex, sig_maxlen, sig, crypto_sign_BYTES);

   printf ("Public Key: %s\n", pk_hex);
   printf ("Secret key: %s\n", sk_hex);
   printf ("Signature:  %s\n", sig_hex);

   if (crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk) == 0)
      printf ("Signature matches.\n");
   else
      printf ("Signature does NOT match.\n");

   printf ("\nAgain, but generate key with a seed.\n");
   unsigned char seed[crypto_sign_SEEDBYTES];
   randombytes_buf (seed, crypto_sign_SEEDBYTES);

   crypto_sign_seed_keypair(pk, sk, seed);
   crypto_sign_detached(sig, NULL, MESSAGE, MESSAGE_LEN, sk);
   sodium_bin2hex (pk_hex, pk_maxlen, pk, crypto_sign_PUBLICKEYBYTES);
   sodium_bin2hex (sk_hex, sk_maxlen, sk, crypto_sign_SECRETKEYBYTES);
   sodium_bin2hex (sig_hex, sig_maxlen, sig, crypto_sign_BYTES);
   sodium_bin2hex (seed_hex, seed_maxlen, seed, crypto_sign_SEEDBYTES);

   printf ("Seed:       %s\n", seed_hex);
   printf ("Public Key: %s\n", pk_hex);
   printf ("Secret key: %s\n", sk_hex);
   printf ("Signature:  %s\n", sig_hex);

   if (crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk) == 0)
      printf ("Signature matches.\n");
   else
      printf ("Signature does NOT match.\n");

   return 0;
}
