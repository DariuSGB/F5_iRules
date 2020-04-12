#########################################################################
# title: BruteForceProtection_HttpResponse.tcl                          #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for protecting against credential stuffing attacks #
# (workaround Bug ID 564046)                                            #
#########################################################################

when RULE_INIT {
	# Variable Definition
	set static::maxtry 5 ; # Maximum failed login attempts
	set static::time 900 ; # Time window for failed login attempts evaluation [seconds]
	set static::bantime 3600 ; # How long the user is banned [seconds]
}

when CLIENT_ACCEPTED priority 100 {
	# Get client IP
	set source_ip [IP::remote_addr]
}

when HTTP_REQUEST priority 100 {
	event HTTP_RESPONSE enable
	event STREAM_MATCHED enable
	STREAM::disable
	set login_access 0
	# Enable login access flag
	if { [class match [string tolower [HTTP::uri] ] contains LOGIN_URI_DG ] } {
		set login_access 1
		# Respond user if exists in blacklist
		if { [table lookup -subtable "blacklist" $source_ip] != "" } {
			HTTP::respond 200 content "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br><a href='javascript:history.back();'>\[Go Back\]</a></body></html>" noserver Connection close
			event HTTP_RESPONSE disable
		}
	}
}

when HTTP_RESPONSE priority 100 {
	if { $login_access } {
		# Configure stream expression when response is JSON
		if {[HTTP::header value Content-Type] starts_with "application/json"} {
			STREAM::expression {=ACCESS_FAIL=}
			STREAM::enable
		}
	event HTTP_RESPONSE disable
	}
}

when STREAM_MATCHED priority 100 {
	if { $login_access } {
		# Increase variable of login attempts
		set key "attempts:$source_ip"
		table add $key 0 indefinite $static::time
		set count [table incr $key]
		# If maximum login attempts value is exceeded, then include user in blacklist
		if { $count >= $static::maxtry } {
			table add -subtable "blacklist" $source_ip "blocked" indefinite $static::bantime
			table delete $key
			log local0. "User Rejected: $source_ip"
		}
	event STREAM_MATCHED disable
	}
}
