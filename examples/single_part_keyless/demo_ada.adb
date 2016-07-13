with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : constant String := "Arbitrary data to hash";
   hash : constant String := Keyless_Hash (message);
begin
   Put_Line ("text: " & message);
   Put_Line ("hash: " & hash);
   Put_Line ("hash length is" & hash'Length'Img);
end Demo_Ada;
