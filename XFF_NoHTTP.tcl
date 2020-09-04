#########################################################################
# title: XFF_NoHTTP.tcl                                                 #
# author: Dario Garrido                                                 #
# date: 20200904                                                        #
# description: iRule for adding XFF header without HTTP profile         #
#########################################################################

when CLIENT_ACCEPTED {
    TCP::collect
}
when CLIENT_DATA {
    set payload [TCP::payload]
    if { ($payload starts_with "GET") || ($payload starts_with "POST") } {
        # Set new header
        set header "X-Forwarded-For: [getfield [IP::client_addr] "%" 1]"
        # Insert header into the HTTP query
	    set n_payload [regsub -- "\r\n\r\n" $payload "\r\n$header\r\n\r\n"]
	    # Clear payload content
	    TCP::payload replace 0 [TCP::payload length] ""
	    # Add new payload modified
	    TCP::payload replace 0 0 $n_payload
    }
    TCP::release
}
