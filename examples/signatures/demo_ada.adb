with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : constant String := "JRM wrote this note.";
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      new_public_sign_key : Public_Sign_Key;
      new_secret_sign_key : Secret_Sign_Key;
      new_signature_seed  : Sign_Key_Seed := Random_Sign_Key_seed;
      new_signature       : Signature;
   begin
      Generate_Sign_Keys (new_public_sign_key, new_secret_sign_key);
      Put_Line ("Public Key: " & As_Hexidecimal (new_public_sign_key));
      Put_Line ("Secret Key: " & As_Hexidecimal (new_secret_sign_key));

      new_signature := Obtain_Signature (message, new_secret_sign_key);
      Put_Line ("Signature:  " & As_Hexidecimal (new_signature));

      if Signature_Matches (message, new_signature, new_public_sign_key) then
         Put_Line ("Signature matches.");
      else
         Put_Line ("Signature does NOT match.");
      end if;

      Put_Line ("");
      Put_Line ("Again, but generate key with a seed");
      Generate_Sign_Keys (new_public_sign_key, new_secret_sign_key, new_signature_seed);
      Put_Line ("Seed:       " & As_Hexidecimal (new_signature_seed));
      Put_Line ("Public Key: " & As_Hexidecimal (new_public_sign_key));
      Put_Line ("Secret Key: " & As_Hexidecimal (new_secret_sign_key));

      new_signature := Obtain_Signature (message, new_secret_sign_key);
      Put_Line ("Signature:  " & As_Hexidecimal (new_signature));

      if Signature_Matches (message, new_signature, new_public_sign_key) then
         Put_Line ("Signature matches.");
      else
         Put_Line ("Signature does NOT match.");
      end if;
   end;

end Demo_Ada;
