#########################################################################
# title: Binary_Coding.tcl                                              #
# author: Dario Garrido                                                 #
# date: 20200502                                                        #
# description: iRule for testing 'binary format' and 'binary scan'      #
# references:                                                           #
# https://www.tcl.tk/man/tcl8.4/TclCmd/binary.htm                       #
#########################################################################

when CLIENT_ACCEPTED {
	# Input string
	set str "1A0"
	# Number de digit to read from the string (* - all)
	set static::digits *
	################################
	# Input string format          #
	# 0: B - Binary (8-bit)        #
	# 1: H - Hexadecimal (8-bit)   #
	# 2: A - Ascii (8-bit)         #
	# 3: c - Integer List (8-bit)  #
	# 4: S - Integer List (16-bit) #
	# 5: I - Integer List (32-bit) #
	# 6: W - Integer List (64-bit) #
	################################
	array set static::format { 0 B 1 H 2 A 3 c 4 S 5 I 6 W }
	
	# Convert to binary
	set binary [binary format $static::format(1)$static::digits $str]
	
	# Convert binary to base64
	set binary_b64 [b64encode $binary]
		
	# Convert from binary
	binary scan $binary $static::format(1)$static::digits output_str
		
	# Print output
	log local0. "Input: $str Output: $output_str Base64: $binary_b64"
	
	# B(str[01101010]) = 0110(6) 1010(a)
	# H(str[abcd])     = 1010(a) 1011(b) 1100(c) 1101(d)
	# A(str[abc])      = 0110(6) 0001(1) 0110(6) 0010(2) 0110(6) 0011(3)
	# c(str[1 2 3])    = 0000(0) 0001(1) 0000(0) 0010(2) 0000(0) 0011(3)
	# S(str[1 2 3])    = 0000(0) 0000(0) 0000(0) 0001(1) 0000(0) 0000(0) 0000(0) 0010(2) 0000(0) 0000(0) 0000(0) 0011(3)
	# I(str[53704892]) = 0000(0) 0011(3) 0011(3) 0011(3) 0111(7) 1000(8) 1011(b) 1100(c)
	# W(str[53704892]) = 0000(0) 0000(0) 0000(0) 0000(0) 0000(0) 0000(0) 0000(0) 0000(0) 0000(0) 0011(3) 0011(3) 0011(3) 0111(7) 1000(8) 1011(b) 1100(c)
}
