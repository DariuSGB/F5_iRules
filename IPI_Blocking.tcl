#########################################################################
# title: IPI_Blocking.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20200510                                                        #
# description: iRule for blocking by IP Intelligent                     #
#########################################################################

when CLIENT_ACCEPTED {
	if {[table lookup -notouch -subtable ip-blocking [IP::client_addr]] eq "" } {
		switch -glob [IP::reputation [IP::client_addr]] {
			*Scanners* {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			*Botnets* {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			*Proxies* {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Denial of Service*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			*Phishing* {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Web Attacks*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				#accept
				log local0. "Blocking IP category:[IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Cloud Provider Networks*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category: [IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Illegal Websites*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category: [IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Infected Sources*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				#accept
				log local0. "Blocking IP category: [IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Spam Sources*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				#accept
				log local0. "Blocking IP category: [IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			"*Windows Exploits*" {
				table set -subtable ip-blocking [IP::client_addr] 1 60
				drop
				log local0. "Blocking IP category: [IP::client_addr] is [IP::reputation [IP::client_addr]]"
			}
			default {
				# No category
				#log local0. "No threat detected in DB for IP [IP::client_addr]"
		}
		}
	} else {
			#IP found in table, drop
			drop
	}
}
