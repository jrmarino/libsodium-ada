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


   ------------------
   --  convert #1  --
   ------------------
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

   ------------------
   --  convert #2  --
   ------------------
   function convert (data : String) return Thin.IC.char_array
   is
      use type Thin.IC.size_t;
      reslen : Thin.IC.size_t := Thin.IC.size_t (data'Length);
      result : Thin.IC.char_array (1 .. reslen);
      arrow  : Thin.IC.size_t := 1;
   begin
      for z in data'Range loop
         result (arrow) := Thin.IC.char (data (z));
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


   -------------------
   --  Random_Word  --
   -------------------
   function Random_Word return Natural32
   is
      result : Thin.NaCl_uint32 := Thin.randombytes_random;
   begin
      return Natural32 (result);
   end Random_Word;


   ---------------------------
   --  Random_Limited_Word  --
   ---------------------------
   function Random_Limited_Word (upper_bound : Natural32) return Natural32
   is
      upper  : Thin.NaCl_uint32 := Thin.NaCl_uint32 (upper_bound);
      result : Thin.NaCl_uint32 := Thin.randombytes_uniform (upper);
   begin
      return Natural32 (result);
   end Random_Limited_Word;


   -------------------
   --  Random_Salt  --
   -------------------
   function Random_Salt return Password_Salt
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Password_Salt'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Salt;


   ------------------------
   --  Random_Short_Key  --
   ------------------------
   function Random_Short_Key return Short_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Short_Key'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Short_Key;


   --------------------------------
   --  Random_Standard_Hash_key  --
   --------------------------------
   function Random_Standard_Hash_key return Standard_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Standard_Key'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Standard_Hash_key;


   -----------------------
   --  Random_Hash_Key  --
   -----------------------
   function Random_Hash_Key (Key_Size : Key_Size_Range) return Any_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Key_Size);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Hash_Key;


   ---------------------------
   --  Derive_Password_Key  --
   ---------------------------
   function Derive_Password_Key
     (criticality  : Data_Criticality := online_interactive;
      passkey_size : Passkey_Size_Range := Positive (Thin.crypto_box_SEEDBYTES);
      password     : String;
      salt         : Password_Salt) return Any_Password_Key
   is
      opslimit         : Thin.NaCl_uint64;
      memlimit         : Thin.IC.size_t;

      password_size    : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (password'Length);
      password_tank    : aliased Thin.IC.char_array := convert (password);
      password_pointer : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (password_tank'Unchecked_Access);
      passkey_size_F   : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (passkey_size);
      passkey_size_C   : constant Thin.IC.size_t := Thin.IC.size_t (passkey_size);
      passkey_tank     : aliased Thin.IC.char_array := (1 .. passkey_size_C => Thin.IC.nul);
      passkey_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (passkey_tank'Unchecked_Access);
      salt_size        : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (salt'Length);
      salt_tank        : aliased Thin.IC.char_array := convert (salt);
      salt_pointer     : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (salt_tank'Unchecked_Access);
   begin
      case criticality is
         when online_interactive =>
            opslimit := Thin.crypto_pwhash_OPSLIMIT_INTERACTIVE;
            memlimit := Thin.crypto_pwhash_MEMLIMIT_INTERACTIVE;
         when moderate =>
            opslimit := Thin.crypto_pwhash_OPSLIMIT_MODERATE;
            memlimit := Thin.crypto_pwhash_MEMLIMIT_MODERATE;
         when highly_sensitive =>
            opslimit := Thin.crypto_pwhash_OPSLIMIT_SENSITIVE;
            memlimit := Thin.crypto_pwhash_MEMLIMIT_SENSITIVE;
      end case;
      declare
         use type Thin.IC.int;
         res : Thin.IC.int;
      begin
         res := Thin.crypto_pwhash (text_out  => passkey_pointer,
                                    outlen    => passkey_size_F,
                                    passwd    => password_pointer,
                                    passwdlen => password_size,
                                    salt      => salt_pointer,
                                    opslimit  => opslimit,
                                    memlimit  => memlimit,
                                    alg       => Thin.crypto_pwhash_ALG_DEFAULT);
         if res /= 0 then
            raise Sodium_Out_Of_Memory with "Derive_Password_Key";
         end if;
      end;
      return convert (password_tank);
   end Derive_Password_Key;

end Sodium.Functions;
