with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : constant String := "JRM wrote this note.";
   cipherlen : constant Positive := Cipher_Length (message);
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      alice_public_key : Public_Box_Key;
      alice_secret_key : Secret_Box_Key;
      bob_public_key   : Public_Box_Key;
      bob_secret_key   : Secret_Box_Key;
      new_nonce        : Box_Nonce := Random_Nonce;
      cipher_text      : Encrypted_Data (1 .. cipherlen);
      clear_text       : String (1 .. message'Length);
   begin
      Generate_Box_Keys (alice_public_key, alice_secret_key);
      Generate_Box_Keys (bob_public_key, bob_secret_key);
      Put_Line ("Alice Public Key: " & As_Hexidecimal (alice_public_key));
      Put_Line ("Alice Secret Key: " & As_Hexidecimal (alice_secret_key));
      Put_Line ("Bob Public Key:   " & As_Hexidecimal (bob_public_key));
      Put_Line ("Bob Secret Key:   " & As_Hexidecimal (bob_secret_key));

      cipher_text := Encrypt_Message (plain_text_message   => message,
                                      recipient_public_key => bob_public_key,
                                      sender_secret_key    => alice_secret_key,
                                      unique_nonce         => new_nonce);
      Put_Line ("CipherText:       " & As_Hexidecimal (cipher_text));

      clear_text := Decrypt_Message (ciphertext           => cipher_text,
                                     sender_public_key    => alice_public_key,
                                     recipient_secret_key => bob_secret_key,
                                     unique_nonce         => new_nonce);
      Put_Line ("Back again:       " & clear_text);
   end;
end Demo_Ada;
