#########################################################################
# title: Trace_HPKP.tcl                                                 #
# author: Dario Garrido                                                 #
# date: 20200812                                                        #
# description: iRule for trace HPKP                                     #
#########################################################################

when HTTP_RESPONSE_RELEASE {
	HTTP::header insert "Public-Key-Pins-Report-Only" [HTTP::header value "Public-Key-Pins"]
	HTTP::header remove "Public-Key-Pins"
}
