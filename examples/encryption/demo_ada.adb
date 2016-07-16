with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message    : constant String := "JRM wrote this note.";
   message2   : constant String := "1972 Miami Dolphins";
   cipherlen  : constant Positive := Cipher_Length (message);
   cipher2len : constant Positive := Cipher_Length (message2);
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
      shared_key       : Box_Shared_Key;
      new_nonce        : Box_Nonce := Random_Nonce;
      cipher_text      : Encrypted_Data (1 .. cipherlen);
      cipher2_text     : Encrypted_Data (1 .. cipher2len);
      clear_text       : String (1 .. message'Length);
      clear_text2      : String (1 .. message2'Length);
      new_box_seed     : Sign_Key_Seed := Random_Box_Key_seed;
   begin
      Generate_Box_Keys (alice_public_key, alice_secret_key);
      Generate_Box_Keys (bob_public_key, bob_secret_key, new_box_seed);
      Put_Line ("Alice Public Key:   " & As_Hexidecimal (alice_public_key));
      Put_Line ("Alice Secret Key:   " & As_Hexidecimal (alice_secret_key));
      Put_Line ("Bob Public Key:     " & As_Hexidecimal (bob_public_key));
      Put_Line ("Bob Secret Key:     " & As_Hexidecimal (bob_secret_key));

      cipher_text := Encrypt_Message (plain_text_message   => message,
                                      recipient_public_key => bob_public_key,
                                      sender_secret_key    => alice_secret_key,
                                      unique_nonce         => new_nonce);
      Put_Line ("CipherText (Alice): " & As_Hexidecimal (cipher_text));

      clear_text := Decrypt_Message (ciphertext           => cipher_text,
                                     sender_public_key    => alice_public_key,
                                     recipient_secret_key => bob_secret_key,
                                     unique_nonce         => new_nonce);
      Put_Line ("Back again:         " & clear_text);

      shared_key := Generate_Shared_Key (recipient_public_key => alice_public_key,
                                         sender_secret_key    => bob_secret_key);
      Put_Line ("");
      Put_Line ("Shared Key (Bob):   " & As_Hexidecimal (shared_key));

      new_nonce := Random_Nonce;
      cipher2_text := Encrypt_Message (plain_text_message => message2,
                                       shared_key         => shared_key,
                                       unique_nonce       => new_nonce);
      Put_Line ("CipherText2 (Bob):  " & As_Hexidecimal (cipher2_text));
      clear_text2 := Decrypt_Message (ciphertext   => cipher2_text,
                                      shared_key   => shared_key,
                                      unique_nonce => new_nonce);
      Put_Line ("Back again:         " & clear_text2);
   end;
end Demo_Ada;
