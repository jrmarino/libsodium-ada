with Sodium.Functions; use Sodium.Functions;
with Ada.Text_IO; use Ada.Text_IO;

procedure Demo_Ada
is
   FF : constant Character := Character'Val (255);
   n1 : String (1 .. 3) := (others => ASCII.NUL);
   n2 : String (1 .. 3) := (others => FF);
   n3 : String (1 .. 3) := (3 => Character'Val (254), others => ASCII.NUL);
   n4 : String (1 .. 3) := (3 => FF, others => ASCII.NUL);
   n5 : String (1 .. 3) := (1 => Character'Val (5), 2 => FF, 3 => FF);
   n6 : Box_Nonce;
   n7 : Symmetric_Nonce;
begin
   if not initialize_sodium_library then
      Put_Line ("Initialization failed");
      return;
   end if;

   n6 := Random_Nonce;
   n7 := Random_Symmetric_Nonce;

   Put_Line ("N1: " & As_Hexidecimal (n1));
   increment_nonce (n1);
   Put_Line ("+1: " & As_Hexidecimal (n1));
   Put_Line ("");

   Put_Line ("N2: " & As_Hexidecimal (n2));
   increment_nonce (n2);
   Put_Line ("+1: " & As_Hexidecimal (n2));
   Put_Line ("");

   Put_Line ("N3: " & As_Hexidecimal (n3));
   increment_nonce (n3);
   Put_Line ("+1: " & As_Hexidecimal (n3));
   Put_Line ("");

   Put_Line ("N4: " & As_Hexidecimal (n4));
   increment_nonce (n4);
   Put_Line ("+1: " & As_Hexidecimal (n4));
   Put_Line ("");

   Put_Line ("N5: " & As_Hexidecimal (n5));
   increment_nonce (n5);
   Put_Line ("+1: " & As_Hexidecimal (n5));
   Put_Line ("");

   Put_Line ("N6: " & As_Hexidecimal (n6));
   increment_nonce (n6);
   Put_Line ("+1: " & As_Hexidecimal (n6));
   Put_Line ("");

   Put_Line ("N7: " & As_Hexidecimal (n7));
   increment_nonce (n7);
   Put_Line ("+1: " & As_Hexidecimal (n7));

end Demo_Ada;
