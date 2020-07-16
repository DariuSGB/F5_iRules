#########################################################################
# title: NoLocation_Port.tcl                                            #
# author: Dario Garrido                                                 #
# date: 20200716                                                        #
# description: iRule for removing port in location header               #
#########################################################################

when HTTP_REQUEST {
	# Capture host header
	set host [HTTP::host]
}

when HTTP_RESPONSE {
	# Capture port and location header
	set location [HTTP::header Location]
	set port [URI::port $location]
	# Create a new location header
	set path [URI::path $location]
	set basename [URI::basename $location]
	set query [URI::query $location]
	# Modify location header
	if { [HTTP::is_redirect] }{
		if { $port eq 80 }{
			HTTP::header replace Location "https://$host$path$basename?$query"
		}
	}
}
