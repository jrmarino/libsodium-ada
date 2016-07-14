--  Thick bindings to Sodium Library

with Sodium.Thin_Binding;

package Sodium.Functions is

   package Thin renames Sodium.Thin_Binding;

   ------------------
   --  Data Types  --
   ------------------

   subtype Standard_Hash is String (1 .. Positive (Thin.crypto_genhash_BYTES));
   subtype Hash_Size_Range is Positive range Positive (Thin.crypto_genhash_BYTES_MIN) ..
                                             Positive (Thin.crypto_genhash_BYTES_MAX);
   subtype Any_Hash is String;

   subtype Standard_Key is String (1 .. Positive (Thin.crypto_genhash_KEYBYTES));
   subtype Key_Size_Range is Positive range Positive (Thin.crypto_genhash_KEYBYTES_MIN) ..
                                            Positive (Thin.crypto_genhash_KEYBYTES_MAX);
   subtype Any_Key is String;

   type Hash_State is private;

   -----------------
   --  Functions  --
   -----------------

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


private

   type Hash_State is record
      output_size : Hash_Size_Range;
      state       : aliased Thin.crypto_generichash_state;
   end record;

   function convert (data : Thin.IC.char_array) return String;

end Sodium.Functions;
