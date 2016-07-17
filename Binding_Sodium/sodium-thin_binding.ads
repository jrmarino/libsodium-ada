--  This file is covered by the Internet Software Consortium (ISC) License
--  Reference: ../License.txt

with System;
with Interfaces.C.Strings;

package Sodium.Thin_Binding is

   package IC  renames Interfaces.C;
   package ICS renames Interfaces.C.Strings;

   ------------------
   --  Data Types  --
   ------------------

   type NaCl_uint64 is mod 2 ** 64;
   type NaCl_uint32 is mod 2 ** 32;
   type NaCl_uint8  is mod 2 ** 8;

   type NaCl_block64 is array (Natural range <>) of NaCl_uint64;
   type NaCl_block8  is array (Natural range <>) of NaCl_uint8;

   type crypto_generichash_blake2b_state is record
      h         : NaCl_block64 (0 .. 7);
      t         : NaCl_block64 (0 .. 1);
      f         : NaCl_block64 (0 .. 1);
      buf       : NaCl_block8  (0 .. 255);
      buflen    : IC.size_t;
      last_node : NaCl_uint8;
      padding64 : NaCl_block8  (0 .. 26);
   end record;

   for crypto_generichash_blake2b_state use record
      h         at 0 range   0 * 8 ..  64 * 8 - 1;
      t         at 0 range  64 * 8 ..  80 * 8 - 1;
      f         at 0 range  80 * 8 ..  96 * 8 - 1;
      buf       at 0 range  96 * 8 .. 352 * 8 - 1;
      buflen    at 0 range 352 * 8 .. 356 * 8 - 1;
      last_node at 0 range 356 * 8 .. 357 * 8 - 1;
      padding64 at 0 range 357 * 8 .. 384 * 8 - 1;
   end record;
   for crypto_generichash_blake2b_state'Size use 384 * 8;
   for crypto_generichash_blake2b_state'Alignment use 64;

   subtype crypto_generichash_state is crypto_generichash_blake2b_state;

   type crypto_generichash_state_Access is access all crypto_generichash_state;
   pragma Convention (C, crypto_generichash_state_Access);

   type crypto_aead_aes256gcm_state is record
      state : NaCl_block8  (0 .. 511);
   end record;
   for crypto_aead_aes256gcm_state'Alignment use 16;

   type crypto_aead_aes256gcm_state_Access is access all crypto_aead_aes256gcm_state;
   pragma Convention (C, crypto_aead_aes256gcm_state_Access);

   type NaCl_uint64_Access is access all NaCl_uint64;
   pragma Convention (C, NaCl_uint64_Access);

   -----------------
   --  Constants  --
   -----------------

   crypto_generichash_blake2b_BYTES_MIN     : constant NaCl_uint8 := 16;
   crypto_generichash_blake2b_BYTES         : constant NaCl_uint8 := 32;
   crypto_generichash_blake2b_BYTES_MAX     : constant NaCl_uint8 := 64;
   crypto_generichash_blake2b_KEYBYTES_MIN  : constant NaCl_uint8 := 16;
   crypto_generichash_blake2b_KEYBYTES      : constant NaCl_uint8 := 32;
   crypto_generichash_blake2b_KEYBYTES_MAX  : constant NaCl_uint8 := 64;
   crypto_generichash_blake2b_SALTBYTES     : constant NaCl_uint8 := 16;
   crypto_generichash_blake2b_PERSONALBYTES : constant NaCl_uint8 := 16;

   crypto_generichash_BYTES_MIN    : NaCl_uint8 renames crypto_generichash_blake2b_BYTES_MIN;
   crypto_generichash_BYTES        : NaCl_uint8 renames crypto_generichash_blake2b_BYTES;
   crypto_generichash_BYTES_MAX    : NaCl_uint8 renames crypto_generichash_blake2b_BYTES_MAX;
   crypto_generichash_KEYBYTES_MIN : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES_MIN;
   crypto_generichash_KEYBYTES     : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES;
   crypto_generichash_KEYBYTES_MAX : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES_MAX;

   crypto_shorthash_siphash24_BYTES    : constant NaCl_uint8 := 8;
   crypto_shorthash_siphash24_KEYBYTES : constant NaCl_uint8 := 16;

   crypto_shorthash_BYTES    : NaCl_uint8 renames crypto_shorthash_siphash24_BYTES;
   crypto_shorthash_KEYBYTES : NaCl_uint8 renames crypto_shorthash_siphash24_KEYBYTES;

   crypto_pwhash_argon2i_ALG_ARGON2I13        : constant IC.int      := 1;
   crypto_pwhash_argon2i_SALTBYTES            : constant NaCl_uint8  := 16;
   crypto_pwhash_argon2i_STRBYTES             : constant NaCl_uint8  := 128;
   crypto_pwhash_argon2i_STRPREFIX            : constant String      := "$argon2i$";
   crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE : constant NaCl_uint64 := 4;
   crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE : constant IC.size_t   := 33554432;
   crypto_pwhash_argon2i_OPSLIMIT_MODERATE    : constant NaCl_uint64 := 6;
   crypto_pwhash_argon2i_MEMLIMIT_MODERATE    : constant IC.size_t   := 134217728;
   crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE   : constant NaCl_uint64 := 8;
   crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE   : constant IC.size_t   := 536870912;

   crypto_pwhash_ALG_DEFAULT        : IC.int      renames crypto_pwhash_argon2i_ALG_ARGON2I13;
   crypto_pwhash_SALTBYTES          : NaCl_uint8  renames crypto_pwhash_argon2i_SALTBYTES;
   crypto_pwhash_STRBYTES           : NaCl_uint8  renames crypto_pwhash_argon2i_STRBYTES;
   crypto_pwhash_STRPREFIX          : String      renames crypto_pwhash_argon2i_STRPREFIX;
   crypto_pwhash_OPSLIMIT_MODERATE  : NaCl_uint64 renames crypto_pwhash_argon2i_OPSLIMIT_MODERATE;
   crypto_pwhash_MEMLIMIT_MODERATE  : IC.size_t   renames crypto_pwhash_argon2i_MEMLIMIT_MODERATE;
   crypto_pwhash_OPSLIMIT_SENSITIVE : NaCl_uint64 renames crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE;
   crypto_pwhash_MEMLIMIT_SENSITIVE : IC.size_t   renames crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE;
   crypto_pwhash_OPSLIMIT_INTERACTIVE : NaCl_uint64
                                        renames crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE;
   crypto_pwhash_MEMLIMIT_INTERACTIVE : IC.size_t
                                        renames crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE;

   crypto_box_curve25519xsalsa20poly1305_SEEDBYTES      : constant NaCl_uint8 := 32;
   crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES : constant NaCl_uint8 := 32;
   crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES : constant NaCl_uint8 := 32;
   crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES  : constant NaCl_uint8 := 32;
   crypto_box_curve25519xsalsa20poly1305_NONCEBYTES     : constant NaCl_uint8 := 24;
   crypto_box_curve25519xsalsa20poly1305_MACBYTES       : constant NaCl_uint8 := 16;
   crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES   : constant NaCl_uint8 := 16;
   crypto_box_curve25519xsalsa20poly1305_ZEROBYTES      : constant NaCl_uint8 :=
     crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES +
       crypto_box_curve25519xsalsa20poly1305_MACBYTES;

   crypto_box_SEEDBYTES    : NaCl_uint8 renames crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
   crypto_box_NONCEBYTES   : NaCl_uint8 renames crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
   crypto_box_MACBYTES     : NaCl_uint8 renames crypto_box_curve25519xsalsa20poly1305_MACBYTES;
   crypto_box_ZEROBYTES    : NaCl_uint8 renames crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
   crypto_box_BOXZEROBYTES : NaCl_uint8 renames crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
   crypto_box_BEFORENMBYTES  : NaCl_uint8
                               renames crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
   crypto_box_PUBLICKEYBYTES : NaCl_uint8
                               renames crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
   crypto_box_SECRETKEYBYTES : NaCl_uint8
                               renames crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
   crypto_box_SEALBYTES : constant NaCl_uint8 := crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES;

   crypto_sign_ed25519_BYTES          : constant NaCl_uint8 := 64;
   crypto_sign_ed25519_SEEDBYTES      : constant NaCl_uint8 := 32;
   crypto_sign_ed25519_PUBLICKEYBYTES : constant NaCl_uint8 := 32;
   crypto_sign_ed25519_SECRETKEYBYTES : constant NaCl_uint8 := 32 + 32;

   crypto_sign_BYTES          : NaCl_uint8 renames crypto_sign_ed25519_BYTES;
   crypto_sign_SEEDBYTES      : NaCl_uint8 renames crypto_sign_ed25519_SEEDBYTES;
   crypto_sign_PUBLICKEYBYTES : NaCl_uint8 renames crypto_sign_ed25519_PUBLICKEYBYTES;
   crypto_sign_SECRETKEYBYTES : NaCl_uint8 renames crypto_sign_ed25519_SECRETKEYBYTES;

   crypto_secretbox_xsalsa20poly1305_KEYBYTES     : constant NaCl_uint8 := 32;
   crypto_secretbox_xsalsa20poly1305_NONCEBYTES   : constant NaCl_uint8 := 24;
   crypto_secretbox_xsalsa20poly1305_MACBYTES     : constant NaCl_uint8 := 16;
   crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES : constant NaCl_uint8 := 16;
   crypto_secretbox_xsalsa20poly1305_ZEROBYTES    : constant NaCl_uint8 :=
     crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES +
       crypto_secretbox_xsalsa20poly1305_MACBYTES;

   crypto_secretbox_KEYBYTES   : NaCl_uint8 renames crypto_secretbox_xsalsa20poly1305_KEYBYTES;
   crypto_secretbox_MACBYTES   : NaCl_uint8 renames crypto_secretbox_xsalsa20poly1305_MACBYTES;
   crypto_secretbox_NONCEBYTES : NaCl_uint8 renames crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
   crypto_secretbox_ZEROBYTES  : NaCl_uint8 renames crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
   crypto_secretbox_BOXZEROBYTES : NaCl_uint8
                                   renames crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

   crypto_auth_hmacsha512256_BYTES    : constant NaCl_uint8 := 32;
   crypto_auth_hmacsha512256_KEYBYTES : constant NaCl_uint8 := 32;

   crypto_auth_BYTES    : NaCl_uint8 renames crypto_auth_hmacsha512256_BYTES;
   crypto_auth_KEYBYTES : NaCl_uint8 renames crypto_auth_hmacsha512256_KEYBYTES;

   crypto_aead_chacha20poly1305_ietf_KEYBYTES  : constant NaCl_uint8 := 32;
   crypto_aead_chacha20poly1305_ietf_NPUBBYTES : constant NaCl_uint8 := 12;
   crypto_aead_chacha20poly1305_ietf_ABYTES    : constant NaCl_uint8 := 16;

   crypto_aead_chacha20poly1305_KEYBYTES       : constant NaCl_uint8 := 32;
   crypto_aead_chacha20poly1305_NPUBBYTES      : constant NaCl_uint8 := 8;
   crypto_aead_chacha20poly1305_ABYTES         : constant NaCl_uint8 := 16;

   crypto_aead_aes256gcm_KEYBYTES              : constant NaCl_uint8 := 32;
   crypto_aead_aes256gcm_NPUBBYTES             : constant NaCl_uint8 := 12;
   crypto_aead_aes256gcm_ABYTES                : constant NaCl_uint8 := 16;

   ------------------------
   --  New C Data Types  --
   ------------------------

   type Password_Hash_Container is array (1 .. Positive (crypto_pwhash_STRBYTES)) of IC.char;
   pragma Convention (C, Password_Hash_Container);

   -----------------
   --  Important  --
   -----------------

   function sodium_init return IC.int;
   pragma Import (C, sodium_init);

   ---------------
   --  Hashing  --
   ---------------

   function crypto_generichash
     (text_out : ICS.chars_ptr;
      outlen   : IC.size_t;
      text_in  : ICS.chars_ptr;
      inlen    : NaCl_uint64;
      key      : ICS.chars_ptr;
      keylen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash);

   function crypto_generichash_init
     (state  : crypto_generichash_state_Access;
      key    : ICS.chars_ptr;
      keylen : IC.size_t;
      outlen : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_init);

   function crypto_generichash_update
     (state   : crypto_generichash_state_Access;
      text_in : ICS.chars_ptr;
      inlen   : NaCl_uint64) return IC.int;
   pragma Import (C, crypto_generichash_update);

   function crypto_generichash_final
     (state    : crypto_generichash_state_Access;
      text_out : ICS.chars_ptr;
      outlen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_final);

   function crypto_shorthash
     (text_out : ICS.chars_ptr;
      text_in  : ICS.chars_ptr;
      inlen    : NaCl_uint64;
      k        : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_shorthash);

   function crypto_pwhash
     (text_out  : ICS.chars_ptr;
      outlen    : NaCl_uint64;
      passwd    : ICS.chars_ptr;
      passwdlen : NaCl_uint64;
      salt      : ICS.chars_ptr;
      opslimit  : NaCl_uint64;
      memlimit  : IC.size_t;
      alg       : IC.int) return IC.int;
   pragma Import (C, crypto_pwhash);

   function crypto_pwhash_str
     (text_out  : out Password_Hash_Container;
      passwd    : ICS.chars_ptr;
      passwdlen : NaCl_uint64;
      opslimit  : NaCl_uint64;
      memlimit  : IC.size_t) return IC.int;
   pragma Import (C, crypto_pwhash_str);

   function crypto_pwhash_str_verify
     (text_str : Password_Hash_Container;
      passwd   : ICS.chars_ptr;
      passwdlen : NaCl_uint64) return IC.int;
   pragma Import (C, crypto_pwhash_str_verify);

   ---------------------
   --  Random Things  --
   ---------------------

   procedure randombytes_buf
     (buf  : System.Address;
      size : IC.size_t);
   pragma Import (C, randombytes_buf);

   function randombytes_random return NaCl_uint32;
   pragma Import (C, randombytes_random);

   function randombytes_uniform (upper_bound : NaCl_uint32) return NaCl_uint32;
   pragma Import (C, randombytes_uniform);

   -----------------------------
   --  Public Key Signatures  --
   -----------------------------

   function crypto_sign_keypair
     (pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign_keypair);

   function crypto_sign_seed_keypair
     (pk   : ICS.chars_ptr;
      sk   : ICS.chars_ptr;
      seed : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign_seed_keypair);

   function crypto_sign
     (sm : ICS.chars_ptr; smlen : NaCl_uint64;
      m  : ICS.chars_ptr; mlen  : NaCl_uint64;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign);

   function crypto_sign_open
     (m  : ICS.chars_ptr; mlen  : NaCl_uint64;
      sm : ICS.chars_ptr; smlen : NaCl_uint64;
      pk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign_open);

   function crypto_sign_detached
     (sig : ICS.chars_ptr; siglen : ICS.chars_ptr;
      m   : ICS.chars_ptr; mlen   : NaCl_uint64;
      sk  : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign_detached);

   function crypto_sign_verify_detached
     (sig : ICS.chars_ptr;
      m   : ICS.chars_ptr; mlen : NaCl_uint64;
      pk  : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_sign_verify_detached);

   -----------------------------
   --  Public Key Encryption  --
   -----------------------------

   function crypto_box_keypair
     (pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_keypair);

   function crypto_box_seed_keypair
     (pk   : ICS.chars_ptr;
      sk   : ICS.chars_ptr;
      seed : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_seed_keypair);

   function crypto_scalarmult_base
     (q : ICS.chars_ptr;
      n : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_scalarmult_base);

   function crypto_box_easy
     (c  : ICS.chars_ptr;
      m  : ICS.chars_ptr; mlen : NaCl_uint64;
      n  : ICS.chars_ptr;
      pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_easy);

   function crypto_box_open_easy
     (m  : ICS.chars_ptr;
      c  : ICS.chars_ptr; clen : NaCl_uint64;
      n  : ICS.chars_ptr;
      pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_open_easy);

   function crypto_box_detached
     (c   : ICS.chars_ptr;
      mac : ICS.chars_ptr;
      m   : ICS.chars_ptr; mlen : NaCl_uint64;
      n   : ICS.chars_ptr;
      pk  : ICS.chars_ptr;
      sk  : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_detached);

   function crypto_box_open_detached
     (m    : ICS.chars_ptr;
      c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr;
      clen : NaCl_uint64;
      n    : ICS.chars_ptr;
      pk   : ICS.chars_ptr;
      sk   : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_open_detached);

   function crypto_box_beforenm
     (k  : ICS.chars_ptr;
      pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_beforenm);

   function crypto_box_easy_afternm
     (c : ICS.chars_ptr;
      m : ICS.chars_ptr; mlen : NaCl_uint64;
      n : ICS.chars_ptr;
      k : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_easy_afternm);

   function crypto_box_open_easy_afternm
     (m : ICS.chars_ptr;
      c : ICS.chars_ptr; clen : NaCl_uint64;
      n : ICS.chars_ptr;
      k : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_open_easy_afternm);

   function crypto_box_detached_afternm
     (c   : ICS.chars_ptr;
      mac : ICS.chars_ptr;
      m   : ICS.chars_ptr; mlen : NaCl_uint64;
      n   : ICS.chars_ptr;
      k   : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_detached_afternm);

   function crypto_box_open_detached_afternm
     (m    : ICS.chars_ptr;
      c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr;
      clen : NaCl_uint64;
      n    : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_open_detached_afternm);

   ----------------------------------
   --  Anonymous Private Messages  --
   ----------------------------------

   function crypto_box_seal
     (c  : ICS.chars_ptr;
      m  : ICS.chars_ptr; mlen : NaCl_uint64;
      pk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_seal);

   function crypto_box_seal_open
     (m  : ICS.chars_ptr;
      c  : ICS.chars_ptr; clen : NaCl_uint64;
      pk : ICS.chars_ptr;
      sk : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_box_seal_open);

   ----------------------------
   --  Symmetric Encryption  --
   ----------------------------

   function crypto_secretbox_easy
     (c : ICS.chars_ptr;
      m : ICS.chars_ptr; mlen : NaCl_uint64;
      n : ICS.chars_ptr;
      k : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_secretbox_easy);

   function crypto_secretbox_open_easy
     (m : ICS.chars_ptr;
      c : ICS.chars_ptr; clen : NaCl_uint64;
      n : ICS.chars_ptr;
      k : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_secretbox_open_easy);

   function crypto_secretbox_detached
     (c   : ICS.chars_ptr;
      mac : ICS.chars_ptr;
      m   : ICS.chars_ptr; mlen : NaCl_uint64;
      n   : ICS.chars_ptr;
      k   : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_secretbox_detached);

   function crypto_secretbox_open_detached
     (m    : ICS.chars_ptr;
      c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr;
      clen : NaCl_uint64;
      n    : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_secretbox_open_detached);

   ------------------------------
   --  Message Authentication  --
   ------------------------------

   function crypto_auth
     (tag     : ICS.chars_ptr;
      text_in : ICS.chars_ptr;
      inlen   : NaCl_uint64;
      k       : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_auth);

   function crypto_auth_verify
     (tag     : ICS.chars_ptr;
      text_in : ICS.chars_ptr;
      inlen   : NaCl_uint64;
      k       : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_auth_verify);

   ----------------------------------
   --  original ChaCha20-Poly1305  --
   ----------------------------------

   function crypto_aead_chacha20poly1305_encrypt
     (c    : ICS.chars_ptr; clen  : NaCl_uint64;
      m    : ICS.chars_ptr; mlen  : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_encrypt);

   function crypto_aead_chacha20poly1305_decrypt
     (m    : ICS.chars_ptr; mlen_p : NaCl_uint64_Access;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen   : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen  : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_decrypt);

   function crypto_aead_chacha20poly1305_encrypt_detached
     (c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr; maclen_p : NaCl_uint64_Access;
      m    : ICS.chars_ptr; mlen     : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen    : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_encrypt_detached);

   function crypto_aead_chacha20poly1305_decrypt_detached
     (m    : ICS.chars_ptr;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen  : NaCl_uint64;
      mac  : ICS.chars_ptr;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_decrypt_detached);

   ------------------------------
   --  IETF ChaCha20-Poly1305  --
   ------------------------------

   function crypto_aead_chacha20poly1305_ietf_encrypt
     (c    : ICS.chars_ptr; clen  : NaCl_uint64;
      m    : ICS.chars_ptr; mlen  : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_ietf_encrypt);

   function crypto_aead_chacha20poly1305_ietf_decrypt
     (m    : ICS.chars_ptr; mlen_p : NaCl_uint64_Access;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen   : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen  : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_ietf_decrypt);

   function crypto_aead_chacha20poly1305_ietf_encrypt_detached
     (c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr; maclen_p : NaCl_uint64_Access;
      m    : ICS.chars_ptr; mlen     : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen    : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_ietf_encrypt_detached);

   function crypto_aead_chacha20poly1305_ietf_decrypt_detached
     (m    : ICS.chars_ptr;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen  : NaCl_uint64;
      mac  : ICS.chars_ptr;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_chacha20poly1305_ietf_decrypt_detached);

   ---------------
   --  AES-GCM  --
   ---------------

   function crypto_aead_aes256gcm_encrypt
     (c    : ICS.chars_ptr; clen  : NaCl_uint64;
      m    : ICS.chars_ptr; mlen  : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_encrypt);

   function crypto_aead_aes256gcm_decrypt
     (m    : ICS.chars_ptr; mlen_p : NaCl_uint64_Access;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen   : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen  : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_decrypt);

   function crypto_aead_aes256gcm_encrypt_detached
     (c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr; maclen_p : NaCl_uint64_Access;
      m    : ICS.chars_ptr; mlen     : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen    : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_encrypt_detached);

   function crypto_aead_aes256gcm_decrypt_detached
     (m    : ICS.chars_ptr;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen  : NaCl_uint64;
      mac  : ICS.chars_ptr;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      npub : ICS.chars_ptr;
      k    : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_decrypt_detached);

   -----------------------------------
   --  AES-GCM with Precalculation  --
   -----------------------------------

   function crypto_aead_aes256gcm_beforenm
     (ctx : crypto_aead_aes256gcm_state_Access;
      k   : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_beforenm);

   function crypto_aead_aes256gcm_encrypt_afternm
     (c    : ICS.chars_ptr; clen_p : NaCl_uint64_Access;
      m    : ICS.chars_ptr; mlen   : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen  : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      ctx  : crypto_aead_aes256gcm_state_Access) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_encrypt_afternm);

   function crypto_aead_aes256gcm_decrypt_afternm
     (m    : ICS.chars_ptr; mlen_p : NaCl_uint64_Access;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen   : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen  : NaCl_uint64;
      npub : ICS.chars_ptr;
      ctx  : crypto_aead_aes256gcm_state_Access) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_decrypt_afternm);

   function crypto_aead_aes256gcm_encrypt_detached_afternm
     (c    : ICS.chars_ptr;
      mac  : ICS.chars_ptr; maclen_p : NaCl_uint64_Access;
      m    : ICS.chars_ptr; mlen     : NaCl_uint64;
      ad   : ICS.chars_ptr; adlen    : NaCl_uint64;
      nsec : ICS.chars_ptr;
      npub : ICS.chars_ptr;
      ctx  : crypto_aead_aes256gcm_state_Access) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_encrypt_detached_afternm);

   function crypto_aead_aes256gcm_decrypt_detached_afternm
     (m    : ICS.chars_ptr;
      nsec : ICS.chars_ptr;
      c    : ICS.chars_ptr; clen  : NaCl_uint64;
      mac  : ICS.chars_ptr;
      ad   : ICS.chars_ptr; adlen : NaCl_uint64;
      npub : ICS.chars_ptr;
      ctx  : crypto_aead_aes256gcm_state_Access) return IC.int;
   pragma Import (C, crypto_aead_aes256gcm_decrypt_detached_afternm);

end Sodium.Thin_Binding;
