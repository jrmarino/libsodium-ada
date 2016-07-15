with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message_1 : constant String := "Arbitrary data to hash";
   message_2 : constant String := "is longer than expected";
   key       : constant String := "123456789 123456789 123456789 12";

   state     : Hash_State;
   hash      : Standard_Hash;
   hash_len  : constant Hash_Size_Range := hash'Length;
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   state := Multipart_Hash_Start (hash_len);
   Multipart_Append (message_1, state);
   Multipart_Append (message_2, state);
   hash := Multipart_Hash_Complete (state);

   Put_Line ("text 1: " & message_1);
   Put_Line ("text 2: " & message_2);
   Put_Line ("hash: " & As_Hexidecimal (hash));

   state := Multipart_Keyed_Hash_Start (key, hash_len);
   Multipart_Append (message_1, state);
   Multipart_Append (message_2, state);
   hash := Multipart_Hash_Complete (state);

   Put_Line ("keyed hash: " & As_Hexidecimal (hash));
end Demo_Ada;
