#########################################################################
# title: SSL_Decrypt.tcl                                                #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for decrypting SSL keys                            #
# https://support.f5.com/csp/article/K12783074                          #
# https://support.f5.com/csp/article/K69625939                          #
#########################################################################

when CLIENTSSL_HANDSHAKE {
	if { [IP::addr [getfield [IP::client_addr] "%" 1] equals 10.1.1.1] } {
        log local0. "\[CSSL\][virtual name] [IP::client_addr]:[TCP::client_port] :: CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
		log local0. "\[CSSL\][virtual name] [IP::client_addr]:[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
	}
}

when SERVERSSL_HANDSHAKE {
	if { [IP::addr [getfield [IP::client_addr] "%" 1] equals 10.1.1.1] } {
        log local0. "\[SSSL\][virtual name] [IP::client_addr]:[TCP::client_port] :: CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
		log local0. "\[SSSL\][virtual name] [IP::client_addr]:[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
	}
}

### Export SSL Keys to file:
# grep -h -o 'CLIENT_RANDOM.*' /var/log/ltm > /shared/tmp/sessionsecrets.pms
# sed -e 's/^.*\(RSA Session-ID\)/\1/;tx;d;:x' /var/log/ltm >> /shared/tmp/sessionsecrets.pms
