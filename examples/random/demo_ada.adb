with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   upper_bound : Natural32 := 16#FFF#;
   Custom_Size : Key_Size_Range := 48;
begin
   Put_Line ("    Full random: " & Random_Word'Img);
   Put_Line ("Limited to $FFF: " & Random_Limited_Word (upper_bound)'Img);
   Put_Line ("    Random salt: " & Random_Salt);
   Put_Line ("   Random short: " & Random_Short_Key);
   Put_Line (" Random Std key: " & Random_Standard_Hash_Key);
   Put_LIne ("Rand 48-bit Key: " & Random_Hash_Key (Custom_Size));
end Demo_Ada;
