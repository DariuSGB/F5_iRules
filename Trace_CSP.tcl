#########################################################################
# title: Trace_CSP.tcl                                                  #
# author: Dario Garrido                                                 #
# date: 20200811                                                        #
# description: iRule for trace CSP policy                               #
#########################################################################

when HTTP_RESPONSE_RELEASE {
        HTTP::header insert "Content-Security-Policy-Report-Only" [HTTP::header value "Content-Security-Policy"]
        HTTP::header remove "Content-Security-Policy"
}
