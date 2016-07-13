--  Thick bindings to Sodium Library

with Sodium.Thin_Binding;

package Sodium.Functions is

   package Thin renames Sodium.Thin_Binding;

   ------------------
   --  Data Types  --
   ------------------

   subtype Standard_Hash is String (1 .. Positive (Thin.crypto_genhash_BYTES) - 1);
   subtype Hash_Size_Range is Positive range Positive (Thin.crypto_genhash_BYTES_MIN) - 1 ..
                                             Positive (Thin.crypto_genhash_BYTES_MAX) - 1;
   subtype Any_Hash is String (Hash_Size_Range);

   subtype Standard_Key is String (1 .. Positive (Thin.crypto_genhash_KEYBYTES) - 1);
   subtype Key_Size_Range is Positive range Positive (Thin.crypto_genhash_KEYBYTES_MIN) - 1 ..
                                            Positive (Thin.crypto_genhash_KEYBYTES_MAX) - 1;
   subtype Any_Key is String (Key_Size_Range);

   -----------------
   --  Functions  --
   -----------------

   function Keyless_Hash (plain_text : String) return Standard_Hash;
   function Keyless_Hash (plain_text  : String;
                          Output_Size : Hash_Size_Range) return Any_Hash;

   function Keyed_Hash (plain_text : String; key : Standard_Key) return Standard_Hash;
   function Keyed_Hash (plain_text  : String;
                        key         : Any_Key;
                        Output_Size : Hash_Size_Range) return Any_Hash;

end Sodium.Functions;
