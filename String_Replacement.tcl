#################################################################################
# title: String_Replacement.tcl                                                 #
# author: Dario Garrido                                                         #
# date: 20200717                                                                #
# description: iRule with some examples of string replacement                   #
# references:                                                                   #
# >>{{string map}}                                                              #
# https://www.tcl.tk/man/tcl8.4/TclCmd/string.htm                               #
# https://wiki.tcl-lang.org/page/string+map                                     #
# https://devcentral.f5.com/s/articles/irules-101-14-tcl-string-commands-part-2 #
# >>{{regsub}}                                                                  #
# http://www.tcl.tk/man/tcl8.4/TclCmd/regsub.htm                                #
# https://wiki.tcl-lang.org/page/regsub                                         #
#################################################################################

when HTTP_REQUEST {
	set replace "/abc"
	set string "/123/456/678/"
	log local0. "string: $string"    ;# string: /123/456/678/
	
	#####################
	# Remove occurrences of '/456' string
	set result1 [string map {"/456" ""} $string]
	log local0. "result1: $result1"  ;# result1: /123/678/
	
	# Replace '/456' by '' and '/678' by 'xyz'
	set result2 [string map {"/456" "" "/678" "/xyz"} $string]
	log local0. "result2: $result2"  ;# result2: /123/xyz/
	
	# Remove '/' character at the end of the string
	set result3 [regsub -- "\/$" $string ""]
	log local0. "result3: $result3"  ;# result3: /123/456/678
	
	# Replace '/456' by the content of $replace
	set result4 [regsub -- "/456" $string "$replace"]
	log local0. "result4: $result4"  ;# result4: /123/abc/678/
	
	# Replace '/456' by the content of $replace and switch regex fields (1) and (2)
	set result5 [regsub -- "(.*)/456(.*)/" $string "\\2$replace\\1/"]
	log local0. "result5: $result5"  ;# result5: /678/abc/123/
	#####################
}
