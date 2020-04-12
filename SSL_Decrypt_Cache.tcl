#########################################################################
# title: SSL_Decrypt_Cache.tcl                                          #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for decrypting SSL keys with cache profile         #
# https://support.f5.com/csp/article/K16700                             #
#########################################################################

when CLIENTSSL_HANDSHAKE {
	# Decrypt SSL key from a client IP
	if { [IP::addr [getfield [IP::client_addr] "%" 1] equals 10.1.1.1] } {
		log local0. "[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
	}
}

when SERVERSSL_HANDSHAKE {
	# Decrypt SSL key from a client IP
	if { [IP::addr [getfield [IP::client_addr] "%" 1] equals 10.1.1.1] } {
		log local0. "[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
	}
}
