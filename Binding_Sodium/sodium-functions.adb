--  This file is covered by the Internet Software Consortium (ISC) License
--  Reference: ../License.txt

package body Sodium.Functions is

   ---------------------------------
   --  initialize_sodium_library  --
   ---------------------------------
   function initialize_sodium_library return Boolean
   is
      use type Thin.IC.int;
      res : Thin.IC.int;
   begin
      res := Thin.sodium_init;
      if res = 1 then
         raise Sodium_Already_Initialized;
      end if;
      return (res = 0);
   end initialize_sodium_library;


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
   function Random_Standard_Hash_Key return Standard_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Standard_Key'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Standard_Hash_Key;


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


   ----------------------------
   --  Random_Sign_Key_seed  --
   ----------------------------
   function Random_Sign_Key_seed return Sign_Key_Seed
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Sign_Key_Seed'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Sign_Key_seed;


   ---------------------------
   --  Random_Box_Key_seed  --
   ---------------------------
   function Random_Box_Key_seed return Box_Key_Seed
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Box_Key_Seed'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Box_Key_seed;


   --------------------
   --  Random_Nonce  --
   --------------------
   function Random_Nonce return Box_Nonce
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Box_Nonce'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Nonce;


   ----------------------------
   --  Random_Symmetric_Key  --
   ----------------------------
   function Random_Symmetric_Key return Symmetric_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Symmetric_Key'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Symmetric_Key;


   ------------------------------
   --  Random_Symmetric_Nonce  --
   ------------------------------
   function Random_Symmetric_Nonce return Symmetric_Nonce
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Symmetric_Nonce'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Symmetric_Nonce;


   -----------------------
   --  Random_Auth_Key  --
   -----------------------
   function Random_Auth_Key return Auth_Key
   is
      bufferlen : constant Thin.IC.size_t := Thin.IC.size_t (Auth_Key'Last);
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_Auth_Key;


   -------------------------
   --  Random_AEAD_Nonce  --
   -------------------------
   function Random_AEAD_Nonce (construction : AEAD_Construction := ChaCha20_Poly1305)
                               return AEAD_Nonce
   is
      function nonce_size return Thin.IC.size_t;
      function nonce_size return Thin.IC.size_t is
      begin
         case construction is
            when ChaCha20_Poly1305 =>
               return Thin.IC.size_t (Thin.crypto_aead_chacha20poly1305_NPUBBYTES);
            when ChaCha20_Poly1305_IETF =>
               return Thin.IC.size_t (Thin.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
            when AES256_GCM =>
               return Thin.IC.size_t (Thin.crypto_aead_aes256gcm_NPUBBYTES);
         end case;
      end nonce_size;
      bufferlen : constant Thin.IC.size_t := nonce_size;
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_AEAD_Nonce;


   -----------------------
   --  Random_AEAD_Key  --
   -----------------------
   function Random_AEAD_Key (construction : AEAD_Construction := ChaCha20_Poly1305)
                               return AEAD_Key
   is
      function key_size return Thin.IC.size_t;
      function key_size return Thin.IC.size_t is
      begin
         case construction is
            when ChaCha20_Poly1305 =>
               return Thin.IC.size_t (Thin.crypto_aead_chacha20poly1305_KEYBYTES);
            when ChaCha20_Poly1305_IETF =>
               return Thin.IC.size_t (Thin.crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            when AES256_GCM =>
               return Thin.IC.size_t (Thin.crypto_aead_aes256gcm_KEYBYTES);
         end case;
      end key_size;
      bufferlen : constant Thin.IC.size_t := key_size;
      buffer : Thin.IC.char_array := (1 .. bufferlen => Thin.IC.nul);
   begin
      Thin.randombytes_buf (buf  => buffer (buffer'First)'Address, size => bufferlen);
      return convert (buffer);
   end Random_AEAD_Key;


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
      return convert (passkey_tank);
   end Derive_Password_Key;


   ------------------------------
   --  Generate_Password_Hash  --
   ------------------------------
   function Generate_Password_Hash (criticality : Data_Criticality := online_interactive;
                                    password    : String) return Any_Hash
   is
      opslimit  : Thin.NaCl_uint64;
      memlimit  : Thin.IC.size_t;
      hash_tank : Thin.Password_Hash_Container;

      password_size    : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (password'Length);
      password_tank    : aliased Thin.IC.char_array := convert (password);
      password_pointer : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (password_tank'Unchecked_Access);
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
         use type Thin.IC.char;
         res : Thin.IC.int;
         product : String (hash_tank'Range);
         lastz   : Natural := 0;
      begin
         res := Thin.crypto_pwhash_str (text_out  => hash_tank,
                                        passwd    => password_pointer,
                                        passwdlen => password_size,
                                        opslimit  => opslimit,
                                        memlimit  => memlimit);
         if res /= 0 then
            raise Sodium_Out_Of_Memory with "Generate_Password_Hash";
         end if;
         for z in hash_tank'Range loop
            if hash_tank (z) = Thin.IC.nul then
               return product (product'First .. lastz);
            end if;
            product (z) := Character (hash_tank (z));
            lastz := z;
         end loop;
         return product;
      end;
   end Generate_Password_Hash;


   -----------------------------
   --  Password_Hash_Matches  --
   -----------------------------
   function Password_Hash_Matches (hash : Any_Hash; password : String) return Boolean
   is
      hash_tank        : Thin.Password_Hash_Container := (others => Thin.IC.nul);
      password_size    : constant Thin.NaCl_uint64 := Thin.NaCl_uint64 (password'Length);
      password_tank    : aliased Thin.IC.char_array := convert (password);
      password_pointer : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (password_tank'Unchecked_Access);
      arrow            : Positive := Thin.Password_Hash_Container'First;
   begin
      for z in hash'Range loop
         hash_tank (arrow) := Thin.IC.char (hash (z));
         arrow := arrow + 1;
      end loop;
      declare
         use type Thin.IC.int;
         res : Thin.IC.int;
      begin
         res := Thin.crypto_pwhash_str_verify (text_str  => hash_tank,
                                               passwd    => password_pointer,
                                               passwdlen => password_size);
         return (res = 0);
      end;
   end Password_Hash_Matches;


   ----------------------
   --  As_Hexidecimal  --
   ----------------------
   function As_Hexidecimal (binary : String) return String
   is
      type byte is mod 2 ** 8;
      subtype octet is String (1 .. 2);
      function Hex (mychar : Character) return octet;

      mask0 : constant byte := 16#F#;
      mask1 : constant byte := 16#F0#;
      zero  : constant Natural := Character'Pos ('0');
      alpha : constant Natural := Character'Pos ('a') - 10;

      function Hex (mychar : Character) return octet
      is
         mybyte : byte := byte (Character'Pos (mychar));
         val0   : byte := (mybyte and mask0);
         val1   : byte := (mybyte and mask1);
         result : octet;
      begin
         case val0 is
            when 0 .. 9   => result (2) := Character'Val (zero + Natural (val0));
            when 10 .. 15 => result (2) := Character'Val (alpha + Natural (val0));
            when others => null;
         end case;
         case val1 is
            when 16#00# => result (1) := '0';
            when 16#10# => result (1) := '1';
            when 16#20# => result (1) := '2';
            when 16#30# => result (1) := '3';
            when 16#40# => result (1) := '4';
            when 16#50# => result (1) := '5';
            when 16#60# => result (1) := '6';
            when 16#70# => result (1) := '7';
            when 16#80# => result (1) := '8';
            when 16#90# => result (1) := '9';
            when 16#A0# => result (1) := 'a';
            when 16#B0# => result (1) := 'b';
            when 16#C0# => result (1) := 'c';
            when 16#D0# => result (1) := 'd';
            when 16#E0# => result (1) := 'e';
            when 16#F0# => result (1) := 'f';
            when others => null;
         end case;
         return result;
      end Hex;

      product : String (1 .. 2 * binary'Length);
      arrow   : Positive := 1;
   begin
      for z in binary'Range loop
         product (arrow .. arrow + 1) := Hex (binary (z));
         arrow := arrow + 2;
      end loop;
      return product;
   end As_Hexidecimal;


   -----------------
   --  As_Binary  --
   -----------------
   function As_Binary (hexidecimal : String; ignore : String := "") return String
   is
      subtype octet is String (1 .. 2);
      function decvalue (byte : octet) return Character;

      pass1     : String := (1 .. hexidecimal'Length => ASCII.NUL);
      real_size : Natural := 0;
      adiff : constant Natural := Character'Pos ('a') - Character'Pos ('A');
      found : Boolean;

      function decvalue (byte : octet) return Character
      is
         position : Natural := 0;
         zero  : constant Natural := Character'Pos ('0');
         alpha : constant Natural := Character'Pos ('A') - 10;
         sixt  : Character renames byte (1);
         ones  : Character renames byte (2);
      begin
         case sixt is
            when '0' .. '9' => position := (Character'Pos (sixt) - zero) * 16;
            when 'A' .. 'F' => position := (Character'Pos (sixt) - alpha) * 16;
            when others =>     null;
         end case;
         case byte (2) is
            when '0' .. '9' => position := position + (Character'Pos (ones) - zero);
            when 'A' .. 'F' => position := position + (Character'Pos (ones) - alpha);
            when others =>     null;
         end case;
         return Character'Val (position);
      end decvalue;

   begin
      for z in hexidecimal'Range loop
         case hexidecimal (z) is
            when '0' .. '9' | 'A' .. 'F' =>
               real_size := real_size + 1;
               pass1 (real_size) := hexidecimal (z);
            when 'a' .. 'f' =>
               real_size := real_size + 1;
               pass1 (real_size) := Character'Val (Character'Pos (hexidecimal (z)) - adiff);
            when others =>
               found := False;
               for y in ignore'Range loop
                  if hexidecimal (z) = ignore (y) then
                     found := True;
                     exit;
                  end if;
               end loop;
               if not found then
                  raise Sodium_Invalid_Input
                    with "As_Binary - illegal character: " & hexidecimal (z);
               end if;
         end case;
      end loop;
      if real_size = 0 then
         raise Sodium_Invalid_Input
           with "As_Binary - no hexidecimal digits found: " & hexidecimal;
      end if;
      if real_size mod 2 /= 0 then
         raise Sodium_Invalid_Input
           with "As_Binary - odd number of hexidecimal digits: " & hexidecimal;
      end if;
      declare
         bin_size : constant Natural := real_size / 2;
         product  : String (1 .. bin_size);
         index    : Natural;
      begin
         for z in 1 .. bin_size loop
            index := z * 2 - 1;
            product (z) := decvalue (pass1 (index .. index + 1));
         end loop;
         return product;
      end;
   end As_Binary;


   -----------------------------
   --  Generate_Sign_Keys #1  --
   -----------------------------
   procedure Generate_Sign_Keys (sign_key_public : out Public_Sign_Key;
                                 sign_key_secret : out Secret_Sign_Key)
   is
      res             : Thin.IC.int;
      public_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_sign_PUBLICKEYBYTES);
      public_key_tank : aliased Thin.IC.char_array := (1 .. public_key_size => Thin.IC.nul);
      public_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (public_key_tank'Unchecked_Access);

      secret_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_sign_SECRETKEYBYTES);
      secret_key_tank : aliased Thin.IC.char_array := (1 .. secret_key_size => Thin.IC.nul);
      secret_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (secret_key_tank'Unchecked_Access);
   begin
      res := Thin.crypto_sign_keypair (pk => public_pointer, sk => secret_pointer);
      sign_key_public := convert (public_key_tank);
      sign_key_secret := convert (secret_key_tank);
   end Generate_Sign_Keys;


   -----------------------------
   --  Generate_Sign_Keys #2  --
   -----------------------------
   procedure Generate_Sign_Keys (sign_key_public : out Public_Sign_Key;
                                 sign_key_secret : out Secret_Sign_Key;
                                 seed            : Sign_Key_Seed)
   is
      res             : Thin.IC.int;
      public_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_sign_PUBLICKEYBYTES);
      public_key_tank : aliased Thin.IC.char_array := (1 .. public_key_size => Thin.IC.nul);
      public_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (public_key_tank'Unchecked_Access);

      secret_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_sign_SECRETKEYBYTES);
      secret_key_tank : aliased Thin.IC.char_array := (1 .. secret_key_size => Thin.IC.nul);
      secret_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (secret_key_tank'Unchecked_Access);
      seed_tank       : aliased Thin.IC.char_array := convert (seed);
      seed_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (seed_tank'Unchecked_Access);
   begin
      res := Thin.crypto_sign_seed_keypair (pk   => public_pointer,
                                            sk   => secret_pointer,
                                            seed => seed_pointer);
      sign_key_public := convert (public_key_tank);
      sign_key_secret := convert (secret_key_tank);
   end Generate_Sign_Keys;


   ------------------------
   --  Obtain_Signature  --
   ------------------------
   function Obtain_Signature (plain_text_message : String;
                              sign_key_secret    : Secret_Sign_Key) return Signature
   is
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (plain_text_message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      secret_tank     : aliased Thin.IC.char_array := convert (sign_key_secret);
      secret_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (secret_tank'Unchecked_Access);

      result_size     : Thin.IC.size_t := Thin.IC.size_t (Signature'Length);
      result_tank     : aliased Thin.IC.char_array := (1 .. result_size => Thin.IC.nul);
      result_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (result_tank'Unchecked_Access);
   begin
      res := Thin.crypto_sign_detached (sig    => result_pointer,
                                        siglen => Thin.ICS.Null_Ptr,
                                        m      => message_pointer,
                                        mlen   => message_size,
                                        sk     => secret_pointer);
      return convert (result_tank);
   end Obtain_Signature;


   -------------------------
   --  Signature_Matches  --
   -------------------------
   function Signature_Matches (plain_text_message : String;
                               sender_signature   : Signature;
                               sender_sign_key    : Public_Sign_Key) return Boolean
   is
      use type Thin.IC.int;
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (plain_text_message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      sendsig_tank    : aliased Thin.IC.char_array := convert (sender_signature);
      sendsig_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (sendsig_tank'Unchecked_Access);
      sendkey_tank    : aliased Thin.IC.char_array := convert (sender_sign_key);
      sendkey_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (sendkey_tank'Unchecked_Access);
   begin
      res := Thin.crypto_sign_verify_detached (sig  => sendsig_pointer,
                                               m    => message_pointer,
                                               mlen => message_size,
                                               pk   => sendkey_pointer);
      return (res = 0);
   end Signature_Matches;


   ----------------------------
   --  Generate_Box_Keys #1  --
   ----------------------------
   procedure Generate_Box_Keys  (box_key_public : out Public_Box_Key;
                                 box_key_secret : out Secret_Box_Key)
   is
      res             : Thin.IC.int;
      public_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_box_PUBLICKEYBYTES);
      public_key_tank : aliased Thin.IC.char_array := (1 .. public_key_size => Thin.IC.nul);
      public_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (public_key_tank'Unchecked_Access);

      secret_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_box_SECRETKEYBYTES);
      secret_key_tank : aliased Thin.IC.char_array := (1 .. secret_key_size => Thin.IC.nul);
      secret_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (secret_key_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_keypair (pk => public_pointer, sk => secret_pointer);
      box_key_public := convert (public_key_tank);
      box_key_secret := convert (secret_key_tank);
   end Generate_Box_Keys;


   ----------------------------
   --  Generate_Box_Keys #2  --
   ----------------------------
   procedure Generate_Box_Keys  (box_key_public : out Public_Box_Key;
                                 box_key_secret : out Secret_Box_Key;
                                 seed           : Box_Key_Seed)
   is
      res             : Thin.IC.int;
      public_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_box_PUBLICKEYBYTES);
      public_key_tank : aliased Thin.IC.char_array := (1 .. public_key_size => Thin.IC.nul);
      public_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (public_key_tank'Unchecked_Access);

      secret_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_box_SECRETKEYBYTES);
      secret_key_tank : aliased Thin.IC.char_array := (1 .. secret_key_size => Thin.IC.nul);
      secret_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (secret_key_tank'Unchecked_Access);
      seed_tank       : aliased Thin.IC.char_array := convert (seed);
      seed_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (seed_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_seed_keypair (pk   => public_pointer,
                                           sk   => secret_pointer,
                                           seed => seed_pointer);
      box_key_public := convert (public_key_tank);
      box_key_secret := convert (secret_key_tank);
   end Generate_Box_Keys;


   ---------------------------
   --  Generate_Shared_Key  --
   ---------------------------
   function Generate_Shared_Key (recipient_public_key : Public_Box_Key;
                                 sender_secret_key    : Secret_Box_Key) return Box_Shared_Key
   is
      res             : Thin.IC.int;
      public_key_tank : aliased Thin.IC.char_array := convert (recipient_public_key);
      public_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (public_key_tank'Unchecked_Access);

      secret_key_tank : aliased Thin.IC.char_array := convert (sender_secret_key);
      secret_pointer  : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (secret_key_tank'Unchecked_Access);
      shared_key_size : Thin.IC.size_t := Thin.IC.size_t (Thin.crypto_box_BEFORENMBYTES);
      shared_key_tank : aliased Thin.IC.char_array := (1 .. shared_key_size => Thin.IC.nul);
      shared_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (shared_key_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_beforenm (k  => shared_pointer,
                                       pk => public_pointer,
                                       sk => secret_pointer);
      return convert (shared_key_tank);
   end Generate_Shared_Key;


   --------------------------
   --  Encrypt_Message #1  --
   --------------------------
   function Encrypt_Message (plain_text_message : String;
                             shared_key         : Box_Shared_Key;
                             unique_nonce       : Box_Nonce) return Encrypted_Data
   is
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (plain_text_message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (shared_key);
      skey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t := Thin.IC.size_t (Cipher_Length (plain_text_message));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_easy_afternm (c    => product_pointer,
                                           m    => message_pointer,
                                           mlen => message_size,
                                           n    => nonce_pointer,
                                           k    => skey_pointer);
      return convert (product_tank);
   end Encrypt_Message;


   --------------------------
   --  Encrypt_Message #2  --
   --------------------------
   function Encrypt_Message (plain_text_message   : String;
                             recipient_public_key : Public_Box_Key;
                             sender_secret_key    : Secret_Box_Key;
                             unique_nonce         : Box_Nonce) return Encrypted_Data
   is
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (plain_text_message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      pkey_tank       : aliased Thin.IC.char_array := convert (recipient_public_key);
      pkey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (pkey_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (sender_secret_key);
      skey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t := Thin.IC.size_t (Cipher_Length (plain_text_message));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);

   begin
      res := Thin.crypto_box_easy (c    => product_pointer,
                                   m    => message_pointer,
                                   mlen => message_size,
                                   n    => nonce_pointer,
                                   pk   => pkey_pointer,
                                   sk   => skey_pointer);
      return convert (product_tank);
   end Encrypt_Message;


   --------------------------
   --  Decrypt_Message #1  --
   --------------------------
   function Decrypt_Message (ciphertext   : Encrypted_Data;
                             shared_key   : Box_Shared_Key;
                             unique_nonce : Box_Nonce) return String
   is
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      cipher_tank     : aliased Thin.IC.char_array := convert (ciphertext);
      cipher_size     : Thin.NaCl_uint64 := Thin.NaCl_uint64 (cipher_tank'Length);
      cipher_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (cipher_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (shared_key);
      skey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t := Thin.IC.size_t (Clear_Text_Length (ciphertext));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_open_easy_afternm (m    => product_pointer,
                                                c    => cipher_pointer,
                                                clen => cipher_size,
                                                n    => nonce_pointer,
                                                k    => skey_pointer);
      return convert (product_tank);
   end Decrypt_Message;


   --------------------------
   --  Decrypt_Message #2  --
   --------------------------
   function Decrypt_Message (ciphertext           : Encrypted_Data;
                             sender_public_key    : Public_Box_Key;
                             recipient_secret_key : Secret_Box_Key;
                             unique_nonce         : Box_Nonce) return String
   is
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      cipher_tank     : aliased Thin.IC.char_array := convert (ciphertext);
      cipher_size     : Thin.NaCl_uint64 := Thin.NaCl_uint64 (cipher_tank'Length);
      cipher_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (cipher_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      pkey_tank       : aliased Thin.IC.char_array := convert (sender_public_key);
      pkey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (pkey_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (recipient_secret_key);
      skey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t := Thin.IC.size_t (Clear_Text_Length (ciphertext));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_open_easy (m    => product_pointer,
                                        c    => cipher_pointer,
                                        clen => cipher_size,
                                        n    => nonce_pointer,
                                        pk   => pkey_pointer,
                                        sk   => skey_pointer);
      return convert (product_tank);
   end Decrypt_Message;


   ---------------------
   --  Cipher_Length  --
   ---------------------
   function Cipher_Length  (plain_text_message : String) return Positive is
   begin
      return plain_text_message'Length + Positive (Thin.crypto_box_MACBYTES);
   end Cipher_Length;


   -------------------------
   --  Clear_Text_Length  --
   -------------------------
   function Clear_Text_Length (ciphertext : Encrypted_Data) return Positive is
   begin
      return ciphertext'Length - Positive (Thin.crypto_box_MACBYTES);
   end Clear_Text_Length;


   ----------------------------
   --  Sealed_Cipher_Length  --
   ----------------------------
   function Sealed_Cipher_Length (plain_text : String) return Positive is
   begin
      return plain_text'Length + Positive (Thin.crypto_box_SEALBYTES);
   end Sealed_Cipher_Length;


   --------------------------------
   --  Sealed_Clear_Text_Length  --
   --------------------------------
   function Sealed_Clear_Text_Length (ciphertext : Sealed_Data) return Positive is
   begin
      return ciphertext'Length - Positive (Thin.crypto_box_SEALBYTES);
   end Sealed_Clear_Text_Length;


   --------------------
   --  Seal_Message  --
   --------------------
   function Seal_Message (plain_text_message   : String;
                          recipient_public_key : Public_Box_Key) return Sealed_Data
   is
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (plain_text_message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      pkey_tank       : aliased Thin.IC.char_array := convert (recipient_public_key);
      pkey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (pkey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t :=
                        Thin.IC.size_t (Sealed_Cipher_Length (plain_text_message));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_seal (c    => product_pointer,
                                   m    => message_pointer,
                                   mlen => message_size,
                                   pk   => pkey_pointer);
      return convert (product_tank);
   end Seal_Message;


   ----------------------
   --  Unseal_Message  --
   ----------------------
   function Unseal_Message (ciphertext           : Sealed_Data;
                            recipient_public_key : Public_Box_Key;
                            recipient_secret_key : Secret_Box_Key) return String
   is
      use type Thin.IC.int;
      use type Thin.IC.size_t;
      res             : Thin.IC.int;
      cipher_tank     : aliased Thin.IC.char_array := convert (ciphertext);
      cipher_size     : Thin.NaCl_uint64 := Thin.NaCl_uint64 (cipher_tank'Length);
      cipher_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (cipher_tank'Unchecked_Access);
      pkey_tank       : aliased Thin.IC.char_array := convert (recipient_public_key);
      pkey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (pkey_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (recipient_secret_key);
      skey_pointer    : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t :=
                        Thin.IC.size_t (Sealed_Clear_Text_Length (ciphertext));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_box_seal_open (m    => product_pointer,
                                        c    => cipher_pointer,
                                        clen => cipher_size,
                                        pk   => pkey_pointer,
                                        sk   => skey_pointer);
      if res = 0 then
         return convert (product_tank);
      end if;
      raise Sodium_Wrong_Recipient;
   end Unseal_Message;


   -------------------------------
   --  Symmetric_Cipher_Length  --
   -------------------------------
   function Symmetric_Cipher_Length (plain_text : String) return Positive is
   begin
      return plain_text'Length + Positive (Thin.crypto_secretbox_MACBYTES);
   end Symmetric_Cipher_Length;


   -----------------------------------
   --  Symmetric_Clear_Text_Length  --
   -----------------------------------
   function Symmetric_Clear_Text_Length (ciphertext : Encrypted_Data) return Positive is
   begin
      return ciphertext'Length - Positive (Thin.crypto_secretbox_MACBYTES);
   end Symmetric_Clear_Text_Length;


   -------------------------
   --  Symmetric_Encrypt  --
   -------------------------
   function Symmetric_Encrypt (clear_text   : String;
                               secret_key   : Symmetric_Key;
                               unique_nonce : Symmetric_Nonce) return Encrypted_Data
   is
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (clear_text);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (secret_key);
      skey_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t :=
                        Thin.IC.size_t (Symmetric_Cipher_Length (clear_text));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_secretbox_easy (c    => product_pointer,
                                         m    => message_pointer,
                                         mlen => message_size,
                                         n    => nonce_pointer,
                                         k    => skey_pointer);
      return convert (product_tank);
   end Symmetric_Encrypt;


   -------------------------
   --  Symmetric_Decrypt  --
   -------------------------
   function Symmetric_Decrypt (ciphertext   : Encrypted_Data;
                               secret_key   : Symmetric_Key;
                               unique_nonce : Symmetric_Nonce) return String
   is
      use type Thin.IC.int;
      res             : Thin.IC.int;
      cipher_tank     : aliased Thin.IC.char_array := convert (ciphertext);
      cipher_size     : Thin.NaCl_uint64 := Thin.NaCl_uint64 (cipher_tank'Length);
      cipher_pointer  : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (cipher_tank'Unchecked_Access);
      nonce_tank      : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer   : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (secret_key);
      skey_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_size    : Thin.IC.size_t :=
                        Thin.IC.size_t (Symmetric_Clear_Text_Length (ciphertext));
      product_tank    : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_secretbox_open_easy (m    => product_pointer,
                                              c    => cipher_pointer,
                                              clen => cipher_size,
                                              n    => nonce_pointer,
                                              k    => skey_pointer);
      if res = 0 then
         return convert (product_tank);
      end if;
      raise Sodium_Symmetric_Failed
        with "Message forged or incorrect secret key";
   end Symmetric_Decrypt;


   -----------------------------------
   --  Generate_Authentication_Tag  --
   -----------------------------------
   function Generate_Authentication_Tag (message : String; authentication_key : Auth_Key)
                                         return Auth_Tag
   is
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (authentication_key);
      skey_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      product_tank    : aliased Thin.IC.char_array := (1 .. Auth_Tag'Length => Thin.IC.nul);
      product_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      res := Thin.crypto_auth (tag     => product_pointer,
                               text_in => message_pointer,
                               inlen   => message_size,
                               k       => skey_pointer);
      return convert (product_tank);
   end Generate_Authentication_Tag;


   -------------------------
   --  Authentic_Message  --
   -------------------------
   function Authentic_Message (message : String; authentication_tag : Auth_Tag;
                               authentication_key : Auth_Key) return Boolean
   is
      use type Thin.IC.int;
      res             : Thin.IC.int;
      message_tank    : aliased Thin.IC.char_array := convert (message);
      message_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      skey_tank       : aliased Thin.IC.char_array := convert (authentication_key);
      skey_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      tag_tank        : aliased Thin.IC.char_array := convert (authentication_tag);
      tag_pointer     : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (tag_tank'Unchecked_Access);
   begin
      res := Thin.crypto_auth_verify (tag     => tag_pointer,
                                      text_in => message_pointer,
                                      inlen   => message_size,
                                      k       => skey_pointer);
      return (res = 0);
   end Authentic_Message;


   -----------------------
   --  increment_nonce  --
   -----------------------
   procedure increment_nonce (nonce : in out String)
   is
      arrow    : Natural := nonce'Last;
      value    : Natural;
      FF       : constant Character := Character'Val (16#FF#);
      ultimate : constant String (nonce'Range) := (others => FF);
   begin
      if nonce = ultimate then
         for z in nonce'Range loop
            nonce (z) := ASCII.NUL;
         end loop;
         return;
      end if;
      loop
         if nonce (arrow) = FF then
            nonce (arrow) := ASCII.NUL;
            arrow := arrow - 1;
         else
            value := Character'Pos (nonce (arrow));
            nonce (arrow) := Character'Val (value + 1);
            exit;
         end if;
      end loop;
   end increment_nonce;


   --------------------------
   --  AEAD_Cipher_Length  --
   --------------------------
   function AEAD_Cipher_Length (plain_text   : String;
                                construction : AEAD_Construction := ChaCha20_Poly1305)
                                return Positive is
   begin
      case construction is
         when ChaCha20_Poly1305 =>
            return plain_text'Length + Positive (Thin.crypto_aead_chacha20poly1305_ABYTES);
         when ChaCha20_Poly1305_IETF =>
            return plain_text'Length + Positive (Thin.crypto_aead_chacha20poly1305_ietf_ABYTES);
         when AES256_GCM =>
            return plain_text'Length + Positive (Thin.crypto_aead_aes256gcm_ABYTES);
      end case;
   end AEAD_Cipher_Length;


   ------------------------------
   --  AEAD_Clear_Text_Length  --
   ------------------------------
   function AEAD_Clear_Text_Length (ciphertext   : Encrypted_Data;
                                    construction : AEAD_Construction := ChaCha20_Poly1305)
                                    return Positive is
   begin
      case construction is
         when ChaCha20_Poly1305 =>
            return ciphertext'Length - Positive (Thin.crypto_aead_chacha20poly1305_ABYTES);
         when ChaCha20_Poly1305_IETF =>
            return ciphertext'Length - Positive (Thin.crypto_aead_chacha20poly1305_ietf_ABYTES);
         when AES256_GCM =>
            return ciphertext'Length - Positive (Thin.crypto_aead_aes256gcm_ABYTES);
      end case;
   end AEAD_Clear_Text_Length;


   --------------------
   --  AEAD_Encrypt  --
   --------------------
   function AEAD_Encrypt (data_to_encrypt : String;
                          additional_data : String;
                          secret_key      : AEAD_Key;
                          unique_nonce    : AEAD_Nonce;
                          construction    : AEAD_Construction := ChaCha20_Poly1305)
                          return Encrypted_Data
   is
      res              : Thin.IC.int;
      message_tank     : aliased Thin.IC.char_array := convert (data_to_encrypt);
      message_size     : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      message_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      metadata_tank    : aliased Thin.IC.char_array := convert (additional_data);
      metadata_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (message_tank'Length);
      metadata_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (message_tank'Unchecked_Access);
      nonce_tank       : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank        : aliased Thin.IC.char_array := convert (secret_key);
      skey_pointer     : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      cipherlen        : Thin.NaCl_uint64 :=
                         Thin.NaCl_uint64 (AEAD_Cipher_Length (data_to_encrypt, construction));
      product_size     : Thin.IC.size_t := Thin.IC.size_t (cipherlen);
      product_tank     : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
   begin
      case construction is
         when ChaCha20_Poly1305 =>
            res := Thin.crypto_aead_chacha20poly1305_encrypt
              (c     => product_pointer,
               clen  => cipherlen,
               m     => message_pointer,
               mlen  => message_size,
               ad    => metadata_pointer,
               adlen => metadata_size,
               nsec  => Thin.ICS.Null_Ptr,
               npub  => nonce_pointer,
               k     => skey_pointer);
         when ChaCha20_Poly1305_IETF =>
            res := Thin.crypto_aead_chacha20poly1305_ietf_encrypt
              (c     => product_pointer,
               clen  => cipherlen,
               m     => message_pointer,
               mlen  => message_size,
               ad    => metadata_pointer,
               adlen => metadata_size,
               nsec  => Thin.ICS.Null_Ptr,
               npub  => nonce_pointer,
               k     => skey_pointer);
         when AES256_GCM =>
            res := Thin.crypto_aead_aes256gcm_encrypt
              (c     => product_pointer,
               clen  => cipherlen,
               m     => message_pointer,
               mlen  => metadata_size,
               ad    => metadata_pointer,
               adlen => metadata_size,
               nsec  => Thin.ICS.Null_Ptr,
               npub  => nonce_pointer,
               k     => skey_pointer);
      end case;
      return convert (product_tank);
   end AEAD_Encrypt;


   --------------------
   --  AEAD_Decrypt  --
   --------------------
   function AEAD_Decrypt (ciphertext      : String;
                          additional_data : String;
                          secret_key      : AEAD_Key;
                          unique_nonce    : AEAD_Nonce;
                          construction    : AEAD_Construction := ChaCha20_Poly1305) return String
   is
      use type Thin.IC.int;
      res            : Thin.IC.int;
      cipher_tank    : aliased Thin.IC.char_array := convert (ciphertext);
      cipher_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (cipher_tank'Length);
      cipher_pointer : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (cipher_tank'Unchecked_Access);

      metadata_tank    : aliased Thin.IC.char_array := convert (additional_data);
      metadata_size    : Thin.NaCl_uint64 := Thin.NaCl_uint64 (metadata_tank'Length);
      metadata_pointer : Thin.ICS.chars_ptr :=
                        Thin.ICS.To_Chars_Ptr (metadata_tank'Unchecked_Access);
      nonce_tank       : aliased Thin.IC.char_array := convert (unique_nonce);
      nonce_pointer    : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (nonce_tank'Unchecked_Access);
      skey_tank        : aliased Thin.IC.char_array := convert (secret_key);
      skey_pointer     : Thin.ICS.chars_ptr := Thin.ICS.To_Chars_Ptr (skey_tank'Unchecked_Access);
      messagelen       : Thin.NaCl_uint64 :=
                         Thin.NaCl_uint64 (AEAD_Clear_Text_Length (ciphertext, construction));
      product_size     : Thin.IC.size_t := Thin.IC.size_t (messagelen);
      product_tank     : aliased Thin.IC.char_array := (1 .. product_size => Thin.IC.nul);
      product_pointer  : Thin.ICS.chars_ptr :=
                         Thin.ICS.To_Chars_Ptr (product_tank'Unchecked_Access);
      product_realsize : aliased Thin.NaCl_uint64;
   begin
      case construction is
         when ChaCha20_Poly1305 =>
            res := Thin.crypto_aead_chacha20poly1305_decrypt
              (m      => product_pointer,
               mlen_p => product_realsize'Unchecked_Access,
               nsec   => Thin.ICS.Null_Ptr,
               c      => cipher_pointer,
               clen   => cipher_size,
               ad     => metadata_pointer,
               adlen  => metadata_size,
               npub   => nonce_pointer,
               k      => skey_pointer);
         when ChaCha20_Poly1305_IETF =>
            res := Thin.crypto_aead_chacha20poly1305_ietf_decrypt
              (m      => product_pointer,
               mlen_p => product_realsize'Unchecked_Access,
               nsec   => Thin.ICS.Null_Ptr,
               c      => cipher_pointer,
               clen   => cipher_size,
               ad     => metadata_pointer,
               adlen  => metadata_size,
               npub   => nonce_pointer,
               k      => skey_pointer);
         when AES256_GCM =>
            res := Thin.crypto_aead_aes256gcm_decrypt
              (m      => product_pointer,
               mlen_p => product_realsize'Unchecked_Access,
               nsec   => Thin.ICS.Null_Ptr,
               c      => cipher_pointer,
               clen   => cipher_size,
               ad     => metadata_pointer,
               adlen  => metadata_size,
               npub   => nonce_pointer,
               k      => skey_pointer);
      end case;

      if res = 0 then
         declare
            result : constant String := convert (product_tank);
         begin
            return result (1 .. Natural (product_realsize));
         end;
      end if;
      raise Sodium_AEAD_Failed
        with "Message verification failed";
   end AEAD_Decrypt;


end Sodium.Functions;
