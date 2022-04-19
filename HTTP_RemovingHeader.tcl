#########################################################################
# title: HTTP_RemovingHeader.tcl                                        #
# author: Dario Garrido                                                 #
# date: 20220419                                                        #
# description: iRule for removing one value of one specific header      #
#########################################################################

when HTTP_REQUEST {
	if { [HTTP::header "access-control-allow-headers"] ne "" } {
		if { [HTTP::header "access-control-allow-headers"] contains "," }{
			set acheaders [split [HTTP::header "access-control-allow-headers"] ","]
			set temp ""
			foreach acheader $acheaders {
				if { $temp eq "" } {
					if { !($acheader contains "X-Web-City-Id") } { set temp "$acheader" }
				} else {
					if { !($acheader contains "X-Web-City-Id") } { set temp "$temp,$acheader" }
				}
			}
			#log local0. "BEFORE: [HTTP::header "access-control-allow-headers"]"
			HTTP::header replace "access-control-allow-headers" $temp
			#log local0. "AFTER: [HTTP::header "access-control-allow-headers"]"
		}
	}
}
