#include <stdio.h>
#include "sodium.h"

#define MESSAGE (const unsigned char *) "From Russia with love."
#define MESSAGE_LEN 22
#define ADDITIONAL_DATA (const unsigned char *) "22 chars"
#define ADDITIONAL_DATA_LEN 8


int main () {
   unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
   unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES] = {0};
   unsigned char ciphertext[MESSAGE_LEN + crypto_aead_chacha20poly1305_ABYTES];
   unsigned long long ciphertext_len;

   if (sodium_init() != 0) {
      return -1;
   }

//   randombytes_buf(key, sizeof key);
//   randombytes_buf(nonce, sizeof nonce);

   crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                        MESSAGE, MESSAGE_LEN,
                                        ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                                        NULL, nonce, key);

   size_t hexlen = sizeof ciphertext * 2 + 1;
   unsigned char hex[hexlen];
   sodium_bin2hex (hex, hexlen, ciphertext, ciphertext_len);

   printf ("ciphertext: %s\n", hex);

   unsigned char decrypted[MESSAGE_LEN + 1] = {0};
   unsigned long long decrypted_len;
   if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                            NULL,
                                            ciphertext, ciphertext_len,
                                            ADDITIONAL_DATA,
                                            ADDITIONAL_DATA_LEN,
                                            nonce, key) == 0)
   printf ("From ciphertext to clear: %s\n", decrypted);
   return 0;
}
