--  Thick bindings to Sodium Library

package body Sodium.Functions is

   -----------------------
   --  Keyless_Hash #1  --
   -----------------------
   function Keyless_Hash (plain_text : String) return Standard_Hash
   is
      res          : Thin.IC.int;
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (Standard_Hash'Length);
      target       : aliased Thin.IC.char_array := (1 .. hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => Thin.ICS.Null_Ptr,
                                      keylen   => 0);
      Thin.ICS.Free (text_pointer);
      return convert (target);
   end Keyless_Hash;


   -----------------------
   --  Keyless_Hash #2  --
   -----------------------
   function Keyless_Hash (plain_text  : String;
                          output_size : Hash_Size_Range) return Any_Hash
   is
      res          : Thin.IC.int;
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (output_size);
      target       : aliased Thin.IC.char_array := (1 .. hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
   begin
      res := Thin.crypto_generichash (text_out => hash_pointer,
                                      outlen   => hash_length,
                                      text_in  => text_pointer,
                                      inlen    => text_length,
                                      key      => Thin.ICS.Null_Ptr,
                                      keylen   => 0);
      Thin.ICS.Free (text_pointer);
      return convert (target);
   end Keyless_Hash;


   ---------------------
   --  Keyed_Hash #1  --
   ---------------------
   function Keyed_Hash (plain_text : String; key : Standard_Key) return Standard_Hash
   is
      res          : Thin.IC.int;
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (Standard_Hash'Length);
      target       : aliased Thin.IC.char_array := (1 .. hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
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
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (key_pointer);
      return convert (target);
   end Keyed_Hash;


   ---------------------
   --  Keyed_Hash #2  --
   ---------------------
   function Keyed_Hash (plain_text  : String;
                        key         : Any_Key;
                        output_size : Hash_Size_Range) return Any_Hash
   is
      res          : Thin.IC.int;
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (output_size);
      target       : aliased Thin.IC.char_array := (1 .. hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
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
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (key_pointer);
      return convert (target);
   end Keyed_Hash;


   ---------------
   --  convert  --
   ---------------
   function convert (data : Thin.IC.char_array) return String
   is
      use type Thin.IC.size_t;
      result : String (1 .. data'Length);
      arrow : Thin.IC.size_t := data'First;
   begin
      for z in result'Range loop
         result (z) := Character (data (arrow));
         arrow := arrow + 1;
      end loop;
      return result;
   end convert;


   ----------------------------
   --  Multipart_Hash_Start  --
   ----------------------------
   function Multipart_Hash_Start (output_size : Hash_Size_Range) return Hash_State
   is
      res    : Thin.IC.int;
      result : Hash_State;
   begin
      result.hash_length := Thin.IC.size_t (output_size);
      res := Thin.crypto_generichash_init (state  => result.state'Unchecked_Access,
                                           key    => Thin.ICS.Null_Ptr,
                                           keylen => 0,
                                           outlen => result.hash_length);
      return result;
   end Multipart_Hash_Start;


   ----------------------------------
   --  Multipart_Keyed_Hash_Start  --
   ----------------------------------
   function Multipart_Keyed_Hash_Start (key : Any_Key;
                                        output_size : Hash_Size_Range) return Hash_State
   is
      res         : Thin.IC.int;
      result      : Hash_State;
      key_length  : constant Thin.IC.size_t := Thin.IC.size_t (key'Length);
      key_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (key);
   begin
      result.hash_length := Thin.IC.size_t (output_size);
      res := Thin.crypto_generichash_init (state  => result.state'Unchecked_Access,
                                           key    => key_pointer,
                                           keylen => key_length,
                                           outlen => result.hash_length);
      Thin.ICS.Free (key_pointer);
      return result;
   end Multipart_Keyed_Hash_Start;


   ------------------------
   --  Multipart_Append  --
   ------------------------
   procedure Multipart_Append (plain_text : String; state : in out Hash_State)
   is
      res          : Thin.IC.int;
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (plain_text'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (plain_text);
   begin
      res := Thin.crypto_generichash_update (state   => state.state'Unchecked_Access,
                                             text_in => text_pointer,
                                             inlen   => text_length);
      Thin.ICS.Free (text_pointer);
   end Multipart_Append;


   -------------------------------
   --  Multipart_Hash_Complete  --
   -------------------------------
   function Multipart_Hash_Complete (state : in out Hash_State) return Any_Hash
   is
      res          : Thin.IC.int;
      target       : aliased Thin.IC.char_array := (1 .. state.hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
   begin
      res := Thin.crypto_generichash_final (state    => state.state'Unchecked_Access,
                                            text_out => hash_pointer,
                                            outlen   => state.hash_length);
      return convert (target);
   end Multipart_Hash_Complete;


   ------------------------
   --  Short_Input_Hash  --
   ------------------------
   function Short_Input_Hash (short_data : String; key : Short_Key) return Short_Hash
   is
      res          : Thin.IC.int;
      hash_length  : constant Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_shorthash_BYTES);
      target       : aliased Thin.IC.char_array := (1 .. hash_length => Thin.IC.nul);
      hash_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (target'Unchecked_Access);
      text_length  : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (short_data'Length);
      text_pointer : Thin.ICS.chars_ptr := Thin.ICS.New_String (short_data);
      key_pointer  : Thin.ICS.chars_ptr := Thin.ICS.New_String (key);
   begin
      res := Thin.crypto_shorthash (text_out => hash_pointer,
                                    text_in  => text_pointer,
                                    inlen    => text_length,
                                    k        => key_pointer);
      Thin.ICS.Free (text_pointer);
      Thin.ICS.Free (key_pointer);
      return convert (target);
   end Short_Input_Hash;


end Sodium.Functions;
