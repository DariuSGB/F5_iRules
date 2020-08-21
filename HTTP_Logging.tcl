#########################################################################
# title: HTTP_Logging.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20200822                                                        #
# description: iRule for logging HTTP requests                          #
#########################################################################

## INITIAL VARIABLE DECLARATION

when RULE_INIT priority 50 {
	# Client IP to log
	set static::clientIP "10.1.1.0/24"
}

## REQUEST PRE HTTP PROFILE

when CLIENT_ACCEPTED priority 50 {
	set logging 0
	if { [IP::addr [IP::client_addr] eq $static::clientIP] } {
		TCP::collect
		set LogString "[IP::client_addr]:[TCP::client_port]"
		set logging 1
	}
}
when CLIENT_DATA priority 50 {
	set offset 0
	log local0. "============================================="
	log local0. "(REQ_PRE) $LogString"
	foreach aHeader [split [TCP::payload] "\r\n"] {
		if { $aHeader ne "" } {
			log local0. $aHeader
			set offset 0
		} else {
			if { $offset eq 2 } { break } else { incr offset }
		}
	}
	TCP::release
	log local0. "============================================="
}

## REQUEST POST HTTP PROFILE

when HTTP_REQUEST priority 50 {
	if {$logging} {
		set LogString "$LogString -> [HTTP::method] [HTTP::host][HTTP::uri]"
		log local0. "============================================="
		log local0. "(REQ) $LogString"
		foreach aHeader [HTTP::header names] {
			log local0. "$aHeader: [HTTP::header value $aHeader]"
		}
		log local0. "============================================="
	}
}

## REQUEST POST HTTP_REQUEST EVENT

when HTTP_REQUEST_RELEASE priority 50 {
	if {$logging} {
		log local0. "============================================="
		log local0. "(REQ_POST) $LogString"
		foreach aHeader [HTTP::header names] {
			log local0. "$aHeader: [HTTP::header value $aHeader]"
		}
		log local0. "============================================="
	}
}

## RESPONSE PRE HTTP PROFILE

when SERVER_CONNECTED priority 50 {
	if {$logging} {
		TCP::collect
	}
}
when SERVER_DATA priority 50 {
    set offset 0
    log local0. "============================================="
    log local0. "(REP_PRE) $LogString"
    foreach aHeader [split [TCP::payload] "\r\n"] {
        if { $aHeader ne "" } {
            log local0. $aHeader
            set offset 0
        } else {
            if { $offset eq 2 } { break } else { incr offset }
        }
    }
    TCP::release
    log local0. "============================================="
}

## RESPONSE POST HTTP PROFILE

when HTTP_RESPONSE priority 50 {
	if {$logging} {
		set LogString "$LogString - [HTTP::status]"
		log local0. "============================================="
		log local0. "(REP) $LogString"
		foreach aHeader [HTTP::header names] {
			log local0. "$aHeader: [HTTP::header value $aHeader]"
		}
		log local0. "============================================="
	}
}

## RESPONSE POST HTTP_RESPONSE EVENT

when HTTP_RESPONSE_RELEASE priority 50 {
	if {$logging} {
		log local0. "============================================="
		log local0. "(REP_POST) $LogString"
		foreach aHeader [HTTP::header names] {
			log local0. "$aHeader: [HTTP::header value $aHeader]"
		}
		log local0. "============================================="
	}
}
