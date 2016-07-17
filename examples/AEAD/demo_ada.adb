with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message   : constant String   := "From Russia with love.";
   metadata  : constant String   := "22 chars";
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      secret_key  : AEAD_Key   := Random_AEAD_Key;
      msg_nonce   : AEAD_Nonce := Random_AEAD_Nonce;
      cipherlen   : constant Positive := AEAD_Cipher_Length (message);
      cipher_text : Encrypted_Data (1 .. cipherlen);
      clear_text  : String (1 .. message'Length);
   begin
      --  Match with C version for comparison's sake
      secret_key (1 .. secret_key'Last) := (others => ASCII.NUL);
      msg_nonce (1 .. msg_nonce'Last)   := (others => ASCII.NUL);

      Put_Line ("Secret Key   (ChaCha20): " & As_Hexidecimal (secret_key));
      Put_Line ("Nonce        (ChaCha20): " & As_Hexidecimal (msg_nonce));

      cipher_text := AEAD_Encrypt (data_to_encrypt => message,
                                   additional_data => metadata,
                                   secret_key      => secret_key,
                                   unique_nonce    => msg_nonce);

      Put_Line ("CipherText   (ChaCha20): " & As_Hexidecimal (cipher_text));

      begin
         clear_text := AEAD_Decrypt (ciphertext      => cipher_text,
                                     additional_data => metadata,
                                     secret_key      => secret_key,
                                     unique_nonce    => msg_nonce);
         Put_Line ("Back again             : " & clear_text);
      exception
         when others => Put_Line ("Convert to clear text failed");
      end;
   end;

   declare
      secret_key  : AEAD_Key   := Random_AEAD_Key (AES256_GCM);
      msg_nonce   : AEAD_Nonce := Random_AEAD_Nonce (AES256_GCM);
      clear_text  : String (1 .. message'Length);
   begin
      Put_Line ("");
      Put_Line ("Secret Key (AES256_GCM): " & As_Hexidecimal (secret_key));
      Put_Line ("Nonce      (AES256_GCM): " & As_Hexidecimal (msg_nonce));

      declare
         cipher_text : Encrypted_Data := 
                       AEAD_Encrypt (data_to_encrypt => message,
                                     additional_data => metadata,
                                     secret_key      => secret_key,
                                     unique_nonce    => msg_nonce,
                                     construction    => AES256_GCM);
      begin
         Put_Line ("CipherText (AES256_GCM): " & As_Hexidecimal (cipher_text));

         clear_text := AEAD_Decrypt (ciphertext      => cipher_text,
                                     additional_data => metadata,
                                     secret_key      => secret_key,
                                     unique_nonce    => msg_nonce,
                                     construction    => AES256_GCM);
         Put_Line ("Back again             : " & clear_text);
      exception
         when others => Put_Line ("Convert to clear text failed");
      end;
   end;

   declare
      secret_key  : AEAD_Key   := Random_AEAD_Key (ChaCha20_Poly1305_IETF);
      msg_nonce   : AEAD_Nonce := Random_AEAD_Nonce (ChaCha20_Poly1305_IETF);
      cipherlen   : constant Positive := AEAD_Cipher_Length (message, ChaCha20_Poly1305_IETF);
      cipher_text : Encrypted_Data (1 .. cipherlen);
      clear_text  : String (1 .. message'Length);
   begin
      Put_Line ("");
      if AES256_GCM_Available then
         Put_Line ("Secret Key   (CC20IETF): " & As_Hexidecimal (secret_key));
         Put_Line ("Nonce        (CC20IETF): " & As_Hexidecimal (msg_nonce));

         cipher_text := AEAD_Encrypt (data_to_encrypt => message,
                                      additional_data => metadata,
                                      secret_key      => secret_key,
                                      unique_nonce    => msg_nonce,
                                      construction    => ChaCha20_Poly1305_IETF);

         Put_Line ("CipherText   (CC20IETF): " & As_Hexidecimal (cipher_text));

         begin
            clear_text := AEAD_Decrypt (ciphertext      => cipher_text,
                                        additional_data => metadata,
                                        secret_key      => secret_key,
                                        unique_nonce    => msg_nonce,
                                        construction    => ChaCha20_Poly1305_IETF);
            Put_Line ("Back again             : " & clear_text);
         exception
            when others => Put_Line ("Convert to clear text failed");
         end;
      else
         Put_Line ("This CPU cannot perform AES256, skipping test ...");
      end if;
   end;
end Demo_Ada;
