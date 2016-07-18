with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   upper_bound : Natural32 := 16#FFF#;
   Custom_Size : Key_Size_Range := 48;
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   Put_Line ("    Full random: " & Random_Word'Img);
   Put_Line ("Limited to $FFF: " & Random_Limited_Word (upper_bound)'Img);
   Put_Line ("    Random salt: " & As_Hexidecimal (Random_Salt));
   Put_Line ("   Random short: " & As_Hexidecimal (Random_Short_Key));
   Put_Line (" Random Std key: " & As_Hexidecimal (Random_Standard_Hash_Key));
   Put_LIne ("Rand 48-bit Key: " & As_Hexidecimal (Random_Hash_Key (Custom_Size)));
end Demo_Ada;
