with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message   : constant String   := "From Russia with love.";
   cipherlen : constant Positive := Symmetric_Cipher_Length (message);
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      secret_key  : Symmetric_Key := Random_Symmetric_Key;
      second_key  : Symmetric_Key := Random_Symmetric_Key;
      first_nonce : Symmetric_Nonce := Random_Symmetric_Nonce;
      cipher_text : Encrypted_Data (1 .. cipherlen);
      clear_text  : String (1 .. message'Length);
   begin
      Put_Line ("Secret Key: " & As_Hexidecimal (secret_key));
      Put_Line ("Second Key: " & As_Hexidecimal (second_key));

      cipher_text := Symmetric_Encrypt (clear_text   => message,
                                        secret_key   => secret_key,
                                        unique_nonce => first_nonce);

      Put_Line ("CipherText: " & As_Hexidecimal (cipher_text));

      clear_text := Symmetric_Decrypt (ciphertext   => cipher_text,
                                       secret_key   => secret_key,
                                       unique_nonce => first_nonce);

      Put_Line ("Back again: " & clear_text);
      Put ("Let another key try to open it ... ");
      begin
         clear_text := Symmetric_Decrypt (ciphertext   => cipher_text,
                                          secret_key   => second_key,
                                          unique_nonce => first_nonce);
      exception
         when others => Put_Line ("That failed as expected.");
      end;
      Put_Line ("Now use the original key after slightly altering the cipher text ...");
      cipher_text (10) := 'Z';
      clear_text := Symmetric_Decrypt (ciphertext   => cipher_text,
                                       secret_key   => secret_key,
                                       unique_nonce => first_nonce);
   end;
end Demo_Ada;
