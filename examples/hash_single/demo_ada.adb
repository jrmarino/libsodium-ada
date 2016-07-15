with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : constant String := "Arbitrary text to hash";
   key     : constant String := "123456789 123456789 123456789 12";
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      hash    : constant String := Keyless_Hash (message);
      minhash : constant String := Keyless_Hash (message, Hash_Size_Range'First);
      maxhash : constant String := Keyless_Hash (message, Hash_Size_Range'Last);
      keyhash : constant String := Keyed_Hash (message, key);
      keyhmin : constant String := Keyed_Hash (message, key, Hash_Size_Range'First);
      keyhmax : constant String := Keyed_Hash (message, key, Hash_Size_Range'Last);
   begin
      Put_Line ("text: " & message);
      Put_Line ("hash: " & hash);
      Put_Line ("hash length is" & hash'Length'Img);
      Put_Line ("");
      Put_Line (minhash);
      Put_Line ("hash length is" & minhash'Length'Img);
      Put_Line ("");
      Put_Line (maxhash);
      Put_Line ("hash length is" & maxhash'Length'Img);
      Put_Line ("");
      Put_Line ("keyed std hash:");
      Put_Line (keyhash);
      Put_Line ("");
      Put_Line ("keyed min hash:");
      Put_Line (keyhmin);
      Put_Line ("");
      Put_Line ("keyed max hash:");
      Put_Line (keyhmax);
   end;
end Demo_Ada;
