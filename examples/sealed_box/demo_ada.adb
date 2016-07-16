with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message   : constant String   := "For your eyes only! XoXo";
   cipherlen : constant Positive := Sealed_Cipher_Length (message);
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      bob_public_key : Public_Box_Key;
      bob_secret_key : Secret_Box_Key;
      dan_public_key : Public_Box_Key;
      dan_secret_key : Secret_Box_Key;
      cipher_text    : Sealed_Data (1 .. cipherlen);
      clear_text     : String (1 .. message'Length);
   begin
      Generate_Box_Keys (bob_public_key, bob_secret_key);
      Generate_Box_Keys (dan_public_key, dan_secret_key);
      Put_Line ("Bob Public Key:         " & As_Hexidecimal (bob_public_key));
      Put_Line ("Bob Secret Key:         " & As_Hexidecimal (bob_secret_key));
      Put_Line ("Dan Public Key:         " & As_Hexidecimal (dan_public_key));

      cipher_text := Seal_Message (plain_text_message   => message,
                                   recipient_public_key => bob_public_key);
      Put_Line ("CipherText (Anonymous): " & As_Hexidecimal (cipher_text));

      clear_text := Unseal_Message (ciphertext           => cipher_text,
                                    recipient_public_key => bob_public_key,
                                    recipient_secret_key => bob_secret_key);
      Put_Line ("Back again:             " & clear_text);
      Put_Line ("Let Dan try to open it ...");
      clear_text := Unseal_Message (ciphertext           => cipher_text,
                                    recipient_public_key => dan_public_key,
                                    recipient_secret_key => dan_secret_key);
   end;
end Demo_Ada;
