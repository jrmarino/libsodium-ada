--  Thick bindings to Sodium Library

package body Sodium.Functions is

   -----------------------
   --  Keyless_Hash #1  --
   -----------------------
   function Keyless_Hash (plain_text : String) return Standard_Hash
   is
      res          : Thin.IC.int;
      target       : Standard_Hash := (others => '_');
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (target'Length);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (target);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => Thin.ICS.Null_Ptr,
                                      keylen   => 0);
      target := Thin.ICS.Value (Item => hash_pointer, Length => hash_length);
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (hash_pointer);
      return target;
   end Keyless_Hash;


   -----------------------
   --  Keyless_Hash #2  --
   -----------------------
   function Keyless_Hash (plain_text  : String;
                          Output_Size : Hash_Size_Range) return Any_Hash
   is
      res          : Thin.IC.int;
      target       : Any_Hash := (1 .. Output_Size => '_');
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (target'Length);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (target);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => Thin.ICS.Null_Ptr,
                                      keylen   => 0);
      target := Thin.ICS.Value (Item => hash_pointer, Length => hash_length);
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (hash_pointer);
      return target;
   end Keyless_Hash;


   ---------------------
   --  Keyed_Hash #1  --
   ---------------------
   function Keyed_Hash (plain_text : String; key : Standard_Key) return Standard_Hash
   is
      res          : Thin.IC.int;
      target       : Standard_Hash := (others => '_');
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (target'Length);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (target);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
      key_length   : constant Thin.IC.size_t := Thin.IC.size_t (key'Length);
      key_pointer  : Thin.ICS.chars_ptr := Thin.ICS.New_String (key);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => key_pointer,
                                      keylen   => key_length);
      target := Thin.ICS.Value (Item => hash_pointer, Length => hash_length);
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (hash_pointer);
      Thin.ICS.Free (key_pointer);
      return target;
   end Keyed_Hash;


   ---------------------
   --  Keyed_Hash #2  --
   ---------------------
   function Keyed_Hash (plain_text  : String;
                        key         : Any_Key;
                        Output_Size : Hash_Size_Range) return Any_Hash
   is
      res          : Thin.IC.int;
      target       : Any_Hash := (1 .. Output_Size => '_');
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (target'Length);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (target);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
      key_length   : constant Thin.IC.size_t := Thin.IC.size_t (key'Length);
      key_pointer  : Thin.ICS.chars_ptr := Thin.ICS.New_String (key);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => key_pointer,
                                      keylen   => key_length);
      target := Thin.ICS.Value (Item => hash_pointer, Length => hash_length);
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (hash_pointer);
      Thin.ICS.Free (key_pointer);
      return target;
   end Keyed_Hash;

end Sodium.Functions;
