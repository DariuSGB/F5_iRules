#########################################################################
# title: DNS_Redirect.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20220228                                                        #
# description: iRule for redirecting root domain (CNAME)                #
#########################################################################

when DNS_REQUEST {
	if { [string tolower [DNS::question type]] eq "a" } {
		if { ( [string tolower [DNS::question name]] eq "example.com" ) } {
			DNS::answer insert [DNS::rr [DNS::question name] 300 IN CNAME "www.[DNS::question name]"]
			DNS::return
		}
	}
}
