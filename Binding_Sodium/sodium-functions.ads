--  This file is covered by the Internet Software Consortium (ISC) License
--  Reference: ../License.txt

with Sodium.Thin_Binding;

package Sodium.Functions is

   package Thin renames Sodium.Thin_Binding;

   ------------------
   --  Data Types  --
   ------------------

   subtype Standard_Hash is String (1 .. Positive (Thin.crypto_generichash_BYTES));
   subtype Hash_Size_Range is Positive range Positive (Thin.crypto_generichash_BYTES_MIN) ..
                                             Positive (Thin.crypto_generichash_BYTES_MAX);
   subtype Any_Hash is String;

   subtype Standard_Key is String (1 .. Positive (Thin.crypto_generichash_KEYBYTES));
   subtype Key_Size_Range is Positive range Positive (Thin.crypto_generichash_KEYBYTES_MIN) ..
                                            Positive (Thin.crypto_generichash_KEYBYTES_MAX);
   subtype Any_Key is String;

   subtype Short_Hash is String (1 .. Positive (Thin.crypto_shorthash_BYTES));
   subtype Short_Key  is String (1 .. Positive (Thin.crypto_shorthash_KEYBYTES));

   subtype Password_Salt is String (1 .. Positive (Thin.crypto_pwhash_SALTBYTES));
   subtype Passkey_Size_Range is Positive range 16 .. 64;
   subtype Any_Password_Key is String;

   subtype Public_Sign_Key is String (1 .. Positive (Thin.crypto_sign_PUBLICKEYBYTES));
   subtype Secret_Sign_Key is String (1 .. Positive (Thin.crypto_sign_SECRETKEYBYTES));
   subtype Sign_Key_Seed   is String (1 .. Positive (Thin.crypto_sign_SEEDBYTES));
   subtype Signature       is String (1 .. Positive (Thin.crypto_sign_BYTES));

   subtype Public_Box_Key  is String (1 .. Positive (Thin.crypto_box_PUBLICKEYBYTES));
   subtype Secret_Box_Key  is String (1 .. Positive (Thin.crypto_box_SECRETKEYBYTES));
   subtype Box_Key_Seed    is String (1 .. Positive (Thin.crypto_box_SEEDBYTES));
   subtype Box_Nonce       is String (1 .. Positive (Thin.crypto_box_NONCEBYTES));
   subtype Box_Shared_Key  is String (1 .. Positive (Thin.crypto_box_BEFORENMBYTES));

   subtype Symmetric_Key   is String (1 .. Positive (Thin.crypto_secretbox_KEYBYTES));
   subtype Symmetric_Nonce is String (1 .. Positive (Thin.crypto_secretbox_NONCEBYTES));

   subtype Auth_Key        is String (1 .. Positive (Thin.crypto_auth_KEYBYTES));
   subtype Auth_Tag        is String (1 .. Positive (Thin.crypto_auth_BYTES));

   subtype Encrypted_Data  is String;
   subtype Sealed_Data     is String;
   subtype AEAD_Nonce      is String;
   subtype AEAD_Key        is String;

   type Natural32 is mod 2 ** 32;

   type Data_Criticality is (online_interactive, moderate, highly_sensitive);
   type AEAD_Construction is (ChaCha20_Poly1305, ChaCha20_Poly1305_IETF, AES256_GCM);

   type Hash_State is private;

   ----------------------
   --  Initialization  --
   ----------------------

   function initialize_sodium_library return Boolean;

   ----------------------
   --  Hash Functions  --
   ----------------------

   function Keyless_Hash (plain_text : String) return Standard_Hash;
   function Keyless_Hash (plain_text  : String;
                          output_size : Hash_Size_Range) return Any_Hash;

   function Keyed_Hash (plain_text : String; key : Standard_Key) return Standard_Hash;
   function Keyed_Hash (plain_text  : String;
                        key         : Any_Key;
                        output_size : Hash_Size_Range) return Any_Hash;

   function Multipart_Hash_Start (output_size : Hash_Size_Range) return Hash_State;
   function Multipart_Keyed_Hash_Start (key : Any_Key;
                                        output_size : Hash_Size_Range) return Hash_State;
   procedure Multipart_Append (plain_text : String; state : in out Hash_State);
   function Multipart_Hash_Complete (state : in out Hash_State) return Any_Hash;

   function Short_Input_Hash (short_data : String; key : Short_Key) return Short_Hash;

   ---------------------
   --  Random Things  --
   ---------------------

   function Random_Word return Natural32;
   function Random_Limited_Word (upper_bound : Natural32) return Natural32;

   function Random_Salt              return Password_Salt;
   function Random_Nonce             return Box_Nonce;
   function Random_Short_Key         return Short_Key;
   function Random_Standard_Hash_Key return Standard_Key;
   function Random_Sign_Key_seed     return Sign_Key_Seed;
   function Random_Box_Key_seed      return Box_Key_Seed;
   function Random_Symmetric_Key     return Symmetric_Key;
   function Random_Symmetric_Nonce   return Symmetric_Nonce;
   function Random_Auth_Key          return Auth_Key;

   function Random_Hash_Key   (Key_Size : Key_Size_Range)
                               return Any_Key;
   function Random_AEAD_Key   (construction : AEAD_Construction := ChaCha20_Poly1305)
                               return AEAD_Key;
   function Random_AEAD_Nonce (construction : AEAD_Construction := ChaCha20_Poly1305)
                               return AEAD_Nonce;

   --------------------------
   --  Password Functions  --
   --------------------------

   function Derive_Password_Key
     (criticality  : Data_Criticality := online_interactive;
      passkey_size : Passkey_Size_Range := Positive (Thin.crypto_box_SEEDBYTES);
      password     : String;
      salt         : Password_Salt) return Any_Password_Key;

   function Generate_Password_Hash
     (criticality : Data_Criticality := online_interactive;
      password    : String) return Any_Hash;

   function Password_Hash_Matches (hash : Any_Hash; password : String) return Boolean;

   ---------------
   --  Helpers  --
   ---------------

   function As_Hexidecimal (binary : String) return String;
   function As_Binary (hexidecimal : String; ignore : String := "") return String;
   procedure increment_nonce (nonce : in out String);

   -----------------------------
   --  Public Key Signatures  --
   -----------------------------

   procedure Generate_Sign_Keys (sign_key_public : out Public_Sign_Key;
                                 sign_key_secret : out Secret_Sign_Key);

   procedure Generate_Sign_Keys (sign_key_public : out Public_Sign_Key;
                                 sign_key_secret : out Secret_Sign_Key;
                                 seed            : Sign_Key_Seed);

   function Obtain_Signature    (plain_text_message : String;
                                 sign_key_secret    : Secret_Sign_Key) return Signature;

   function Signature_Matches   (plain_text_message : String;
                                 sender_signature   : Signature;
                                 sender_sign_key    : Public_Sign_Key) return Boolean;

   -----------------------------
   --  Public Key Encryption  --
   -----------------------------

   procedure Generate_Box_Keys  (box_key_public : out Public_Box_Key;
                                 box_key_secret : out Secret_Box_Key);

   procedure Generate_Box_Keys  (box_key_public : out Public_Box_Key;
                                 box_key_secret : out Secret_Box_Key;
                                 seed           : Box_Key_Seed);

   function Generate_Shared_Key (recipient_public_key : Public_Box_Key;
                                 sender_secret_key    : Secret_Box_Key) return Box_Shared_Key;

   function Encrypt_Message     (plain_text_message   : String;
                                 recipient_public_key : Public_Box_Key;
                                 sender_secret_key    : Secret_Box_Key;
                                 unique_nonce         : Box_Nonce) return Encrypted_Data;

   function Encrypt_Message     (plain_text_message   : String;
                                 shared_key           : Box_Shared_Key;
                                 unique_nonce         : Box_Nonce) return Encrypted_Data;

   function Decrypt_Message     (ciphertext           : Encrypted_Data;
                                 sender_public_key    : Public_Box_Key;
                                 recipient_secret_key : Secret_Box_Key;
                                 unique_nonce         : Box_Nonce) return String;

   function Decrypt_Message     (ciphertext           : Encrypted_Data;
                                 shared_key           : Box_Shared_Key;
                                 unique_nonce         : Box_Nonce) return String;

   function Cipher_Length       (plain_text_message   : String) return Positive;
   function Clear_Text_Length   (ciphertext           : Encrypted_Data) return Positive;

   ----------------------------------
   --  Anonymous Private Messages  --
   ----------------------------------

   function Seal_Message        (plain_text_message   : String;
                                 recipient_public_key : Public_Box_Key) return Sealed_Data;

   function Unseal_Message      (ciphertext           : Sealed_Data;
                                 recipient_public_key : Public_Box_Key;
                                 recipient_secret_key : Secret_Box_Key) return String;

   function Sealed_Cipher_Length     (plain_text : String) return Positive;
   function Sealed_Clear_Text_Length (ciphertext : Sealed_Data) return Positive;

   ----------------------------
   --  Symmetric Encryption  --
   ----------------------------

   function Symmetric_Encrypt (clear_text   : String;
                               secret_key   : Symmetric_Key;
                               unique_nonce : Symmetric_Nonce) return Encrypted_Data;

   function Symmetric_Decrypt (ciphertext   : Encrypted_Data;
                               secret_key   : Symmetric_Key;
                               unique_nonce : Symmetric_Nonce) return String;

   function Symmetric_Cipher_Length     (plain_text : String) return Positive;
   function Symmetric_Clear_Text_Length (ciphertext : Encrypted_Data) return Positive;

   ------------------------------
   --  Message Authentication  --
   ------------------------------

   function Generate_Authentication_Tag (message : String; authentication_key : Auth_Key)
                                         return Auth_Tag;

   function Authentic_Message (message : String; authentication_tag : Auth_Tag;
                               authentication_key : Auth_Key) return Boolean;

   -----------------------------------------------------
   --  Authenticated Encryption with Additional Data  --
   -----------------------------------------------------

   function AEAD_Encrypt (data_to_encrypt : String;
                          additional_data : String;
                          secret_key      : AEAD_Key;
                          unique_nonce    : AEAD_Nonce;
                          construction    : AEAD_Construction := ChaCha20_Poly1305)
                          return Encrypted_Data;

   function AEAD_Decrypt (ciphertext      : Encrypted_Data;
                          additional_data : String;
                          secret_key      : AEAD_Key;
                          unique_nonce    : AEAD_Nonce;
                          construction    : AEAD_Construction := ChaCha20_Poly1305)
                          return String;

   function AEAD_Cipher_Length     (plain_text   : String;
                                    construction : AEAD_Construction := ChaCha20_Poly1305)
                                    return Positive;

   function AEAD_Clear_Text_Length (ciphertext   : Encrypted_Data;
                                    construction : AEAD_Construction := ChaCha20_Poly1305)
                                    return Positive;

   function AES256_GCM_Available return Boolean;

   ------------------
   --  Exceptions  --
   ------------------

   Sodium_Out_Of_Memory       : exception;
   Sodium_Already_Initialized : exception;
   Sodium_Invalid_Input       : exception;
   Sodium_Wrong_Recipient     : exception;
   Sodium_Symmetric_Failed    : exception;
   Sodium_AEAD_Failed         : exception;

private

   type Hash_State is record
      hash_length : Thin.IC.size_t;
      state       : aliased Thin.crypto_generichash_state;
   end record;

   function convert (data : Thin.IC.char_array) return String;
   function convert (data : String) return Thin.IC.char_array;

end Sodium.Functions;
