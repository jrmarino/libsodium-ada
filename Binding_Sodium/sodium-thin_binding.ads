--  Low-level C routines for Sodium Library API

with Interfaces.C.Strings;

package Sodium.Thin_Binding is

   package IC  renames Interfaces.C;
   package ICS renames Interfaces.C.Strings;

   ------------------
   --  Data Types  --
   ------------------

   type NaCl_uint64 is mod 2 ** 64;
   type NaCl_uint8  is mod 2 ** 8;

   type NaCl_block64 is array (Natural range <>) of NaCl_uint64;
   type NaCl_block8  is array (Natural range <>) of NaCl_uint8;

   pragma Pack (NaCl_block64);
   pragma Pack (NaCl_block8);

   type crypto_generichash_blake2b_state is record
      h         : NaCl_block64 (0 .. 7);
      t         : NaCl_block64 (0 .. 1);
      f         : NaCl_block64 (0 .. 1);
      buf       : NaCl_block8  (0 .. 255);
      buflen    : IC.size_t;
      last_node : NaCl_uint8;
   end record;

   subtype crypto_generichash_state is crypto_generichash_blake2b_state;

   type crypto_generichash_blake2b_state_Access is access all crypto_generichash_state;
   pragma Convention (C, crypto_generichash_blake2b_state_Access);

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

   crypto_genhash_BYTES_MIN    : NaCl_uint8 renames crypto_generichash_blake2b_BYTES_MIN;
   crypto_genhash_BYTES        : NaCl_uint8 renames crypto_generichash_blake2b_BYTES;
   crypto_genhash_BYTES_MAX    : NaCl_uint8 renames crypto_generichash_blake2b_BYTES_MAX;
   crypto_genhash_KEYBYTES_MIN : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES_MIN;
   crypto_genhash_KEYBYTES     : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES;
   crypto_genhash_KEYBYTES_MAX : NaCl_uint8 renames crypto_generichash_blake2b_KEYBYTES_MAX;

   -----------------
   --  Important  --
   -----------------

   function sodium_init return IC.int;
   pragma Import (C, sodium_init);

   ---------------
   --  Hashing  --
   ---------------

   function crypto_generichash_bytes return IC.size_t;
   pragma Import (C, crypto_generichash_bytes);

   function crypto_generichash_bytes_min return IC.size_t;
   pragma Import (C, crypto_generichash_bytes_min);

   function crypto_generichash_bytes_max return IC.size_t;
   pragma Import (C, crypto_generichash_bytes_max);

   function crypto_generichash_keybytes return IC.size_t;
   pragma Import (C, crypto_generichash_keybytes);

   function crypto_generichash_keybytes_min return IC.size_t;
   pragma Import (C, crypto_generichash_keybytes_min);

   function crypto_generichash_keybytes_max return IC.size_t;
   pragma Import (C, crypto_generichash_keybytes_max);

   function crypto_generichash_primitive return ICS.chars_ptr;
   pragma Import (C, crypto_generichash_primitive);

   function crypto_generichash (text_out : ICS.chars_ptr;
                                outlen   : IC.size_t;
                                text_in  : ICS.chars_ptr;
                                inlen    : NaCl_uint64;
                                key      : ICS.chars_ptr;
                                keylen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash);

   function crypto_generichash_init (state  : crypto_generichash_blake2b_state_Access;
                                     key    : ICS.chars_ptr;
                                     keylen : IC.size_t;
                                     outlen : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_init);

   function crypto_generichash_update (state   : crypto_generichash_blake2b_state_Access;
                                       text_in : ICS.chars_ptr;
                                       inlen   : NaCl_uint64) return IC.int;
   pragma Import (C, crypto_generichash_update);

   function crypto_generichash_final (state    : crypto_generichash_blake2b_state_Access;
                                      text_out : ICS.chars_ptr;
                                      outlen   : IC.size_t) return IC.int;
   pragma Import (C, crypto_generichash_final);

end Sodium.Thin_Binding;