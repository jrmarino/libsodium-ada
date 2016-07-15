with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   password : constant String := "Correct Horse Battery Staple";
   salt     : constant String := "123456789+123456";
   passkey  : constant String := Derive_Password_Key (password => password, salt => salt);
begin
   Put_Line ("password: " & password);
   Put_Line ("pass key: " & passkey);
end Demo_Ada;
