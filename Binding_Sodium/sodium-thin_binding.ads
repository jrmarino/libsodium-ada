--  Low-level C routines for Sodium Library API

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

   crypto_pwhash_argon2i_ALG_ARGON2I13        : constant NaCl_uint8  := 1;
   crypto_pwhash_argon2i_SALTBYTES            : constant NaCl_uint8  := 16;
   crypto_pwhash_argon2i_STRBYTES             : constant NaCl_uint8  := 128;
   crypto_pwhash_argon2i_STRPREFIX            : constant String      := "$argon2i$";
   crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE : constant NaCl_uint64 := 4;
   crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE : constant NaCl_uint64 := 33554432;
   crypto_pwhash_argon2i_OPSLIMIT_MODERATE    : constant NaCl_uint64 := 6;
   crypto_pwhash_argon2i_MEMLIMIT_MODERATE    : constant NaCl_uint64 := 134217728;
   crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE   : constant NaCl_uint64 := 8;
   crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE   : constant NaCl_uint64 := 536870912;

   crypto_pwhash_ALG_DEFAULT        : NaCl_uint8  renames crypto_pwhash_argon2i_ALG_ARGON2I13;
   crypto_pwhash_SALTBYTES          : NaCl_uint8  renames crypto_pwhash_argon2i_SALTBYTES;
   crypto_pwhash_STRBYTES           : NaCl_uint8  renames crypto_pwhash_argon2i_STRBYTES;
   crypto_pwhash_STRPREFIX          : String      renames crypto_pwhash_argon2i_STRPREFIX;
   crypto_pwhash_OPSLIMIT_MODERATE  : NaCl_uint64 renames crypto_pwhash_argon2i_OPSLIMIT_MODERATE;
   crypto_pwhash_MEMLIMIT_MODERATE  : NaCl_uint64 renames crypto_pwhash_argon2i_MEMLIMIT_MODERATE;
   crypto_pwhash_OPSLIMIT_SENSITIVE : NaCl_uint64 renames crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE;
   crypto_pwhash_MEMLIMIT_SENSITIVE : NaCl_uint64 renames crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE;
   crypto_pwhash_OPSLIMIT_INTERACTIVE : NaCl_uint64
                                        renames crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE;
   crypto_pwhash_MEMLIMIT_INTERACTIVE : NaCl_uint64
                                        renames crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE;

   -----------------
   --  Important  --
   -----------------

   function sodium_init return IC.int;
   pragma Import (C, sodium_init);

   ---------------
   --  Hashing  --
   ---------------

   function crypto_generichash (text_out : ICS.chars_ptr;
                                outlen   : IC.size_t;
                                text_in  : ICS.chars_ptr;
                                inlen    : NaCl_uint64;
                                key      : ICS.chars_ptr;
                                keylen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash);

   function crypto_generichash_init (state  : crypto_generichash_state_Access;
                                     key    : ICS.chars_ptr;
                                     keylen : IC.size_t;
                                     outlen : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_init);

   function crypto_generichash_update (state   : crypto_generichash_state_Access;
                                       text_in : ICS.chars_ptr;
                                       inlen   : NaCl_uint64) return IC.int;
   pragma Import (C, crypto_generichash_update);

   function crypto_generichash_final (state    : crypto_generichash_state_Access;
                                      text_out : ICS.chars_ptr;
                                      outlen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_final);

   function crypto_shorthash (text_out : ICS.chars_ptr;
                              text_in  : ICS.chars_ptr;
                              inlen    : NaCl_uint64;
                              k        : ICS.chars_ptr) return IC.int;
   pragma Import (C, crypto_shorthash);

   function crypto_pwhash (text_out  : ICS.chars_ptr;
                           outlen    : NaCl_uint64;
                           passwd    : ICS.chars_ptr;
                           passwdlen : NaCl_uint64;
                           salt      : ICS.chars_ptr;
                           opslimit  : NaCl_uint64;
                           memlimit  : IC.size_t;
                           alg       : IC.int) return IC.int;
   pragma Import (C, crypto_pwhash);

--     function crypto_pwhash_str (
--     int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES],
--                        const char * const passwd,
--                        unsigned long long passwdlen,
--                        unsigned long long opslimit,
--                        size_t memlimit);
--  int crypto_pwhash_str_verify(const char str[crypto_pwhash_STRBYTES],
--                               const char * const passwd,
--                               unsigned long long passwdlen);

   ---------------------
   --  Random Things  --
   ---------------------

   procedure randombytes_buf (buf : System.Address; size : IC.size_t);
   pragma Import (C, randombytes_buf);

   function randombytes_random return NaCl_uint32;
   pragma Import (C, randombytes_random);

   function randombytes_uniform (upper_bound : NaCl_uint32) return NaCl_uint32;
   pragma Import (C, randombytes_uniform);

end Sodium.Thin_Binding;
