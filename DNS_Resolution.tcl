#########################################################################
# title: DNS_Resolution.tcl                                             #
# author: Dario Garrido                                                 #
# date: 20200419                                                        #
# description: iRule for resolving DNS name                             #
# https://clouddocs.f5.com/api/irules/resolv__lookup.html               #
#########################################################################

when RULE_INIT {
    # Set DNS IP
    set static::dns_vs 10.130.40.40
}

when CLIENT_ACCEPTED {
    # Send DNS query
    set IP_list [RESOLV::lookup @$static::dns_vs -a "web1.springfield.com"]
    if { $IP_list eq "" } {
        # DNS query fails
        log local0. "Domain \"web1.springfield.com\" doesn't exist"
    } else {
        # Send request to the first IP from the list
        node [lindex $IP_list 0]
    }
}
