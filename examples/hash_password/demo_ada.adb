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
   declare
      hash : constant Any_Hash :=
         Generate_Password_Hash (criticality => highly_sensitive, password => password);
   begin
      Put_Line ("hash: " & hash);
      if Password_Hash_Matches (hash => hash, password => password) then
         Put_Line ("Hash verification passed");
      else
         Put_Line ("Hash verification failed");
      end if;
   end;
end Demo_Ada;
