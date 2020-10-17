#########################################################################
# title: Unchunking_Response.tcl                                        #
# author: Dario Garrido                                                 #
# date: 20201017                                                        #
# description: iRule for forcing server to not use chunked encoding     #
#########################################################################

when HTTP_REQUEST {
    HTTP::header remove "Accept-Encoding"
    if { [HTTP::version] eq "1.1" } {
        if { [HTTP::header is_keepalive] } {
            HTTP::header replace "Connection" "Keep-Alive"
        }
        HTTP::version "1.0"
    }
}

when HTTP_RESPONSE {
    if { [HTTP::header "Content-Type"] starts_with "text/html" } {
        set clen [HTTP::header "Content-Length"]
        if { $clen > 0 } {
            HTTP::collect $clen
        }
    }
}

when HTTP_RESPONSE_DATA {
    set n_payload "[string map {"http:" "https:"} [HTTP::payload]]"
    HTTP::payload replace 0 [HTTP::payload length] $n_payload
    unset n_payload
    HTTP::release
}
