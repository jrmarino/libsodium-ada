--  Thick bindings to Sodium Library

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

   type Natural32 is mod 2 ** 32;

   type Data_Criticality is (online_interactive, moderate, highly_sensitive);

   type Hash_State is private;

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
   function Random_Short_Key         return Short_Key;
   function Random_Standard_Hash_key return Standard_Key;
   function Random_Hash_Key (Key_Size : Key_Size_Range) return Any_Key;

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

   ------------------
   --  Exceptions  --
   ------------------

   Sodium_Out_Of_Memory : exception;

private

   type Hash_State is record
      hash_length : Thin.IC.size_t;
      state       : aliased Thin.crypto_generichash_state;
   end record;

   function convert (data : Thin.IC.char_array) return String;
   function convert (data : String) return Thin.IC.char_array;

end Sodium.Functions;
