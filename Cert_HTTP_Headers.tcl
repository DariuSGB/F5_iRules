#########################################################################
# title: Cert_HTTP_Headers.tcl                                          #
# author: Dario Garrido                                                 #
# date: 20201230                                                        #
# description: iRule for injecting HTTP headers with client cert info   #
#########################################################################

when CLIENTSSL_CLIENTCERT {
	set ssl_cert [SSL::cert 0]
	set subject [X509::subject $ssl_cert]
	set issuer [X509::issuer $ssl_cert]
	set valid_from [X509::not_valid_before $ssl_cert]
	set valid_to [X509::not_valid_after $ssl_cert]
	session add ssl [SSL::sessionid] [list [b64encode $ssl_cert] $subject $issuer $valid_from $valid_to] 1800
}

when HTTP_REQUEST {
	set values [session lookup ssl [SSL::sessionid] ]
	if { [lindex $values 0] != "" } {
		HTTP::header insert cert_b64 [lindex $values 0]
		HTTP::header insert cert_subject [lindex $values 1]
		HTTP::header insert cert_issuer [lindex $values 2]
		HTTP::header insert cert_valid_from [lindex $values 3]
		HTTP::header insert cert_valid_to [lindex $values 4]
	}
}
