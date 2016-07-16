with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   message : String := "Are you sure I wrote this?";
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   declare
      tag : Auth_Tag;
      my_key : Auth_Key := Random_Auth_Key;
   begin
      tag :=  Generate_Authentication_Tag (message => message,
                                           authentication_key => my_key);
      Put_Line (" Message: " & message);
      Put_Line ("Auth Tag: " & As_Hexidecimal (tag));
      Put      ("Test unmodified message and tag ... ");
      if Authentic_Message (authentication_tag => tag,
                            message => message,
                            authentication_key => my_key)
      then
         Put_Line ("Authentic");
      else
         Put_Line ("It's a fake!");
      end if;
      Put_Line ("");
      message (14) := 'i';
      Put_Line (" Message: " & message);
      Put      ("Test modified message and real tag ... ");

      if Authentic_Message (authentication_tag => tag,
                            message => message,
                            authentication_key => my_key)
      then
         Put_Line ("Authentic");
      else
         Put_Line ("It's a fake!");
      end if;
   end;
end Demo_Ada;
