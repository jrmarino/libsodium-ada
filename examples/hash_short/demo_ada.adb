with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : constant String := "Sparkling water";
   key     : constant String := "123456789 123456";
   hash    : constant String := Short_Input_Hash (message, key);
begin
   Put_Line ("text: " & message);
   Put_Line ("hash: " & hash);
end Demo_Ada;
