#########################################################################
# title: HTTP_SecurityHeaders.tcl                                       #
# author: Dario Garrido                                                 #
# date: 20200811                                                        #
# description: iRule for adding HTTP security headers                   #
#########################################################################

when RULE_INIT {
	set static::fqdn_pin "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1TZQrU06KUKg="	;# openssl x509 -pubkey < tls.crt | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
	set static::max_age 15552000										;# 180 days
}

when HTTP_REQUEST {
	HTTP::respond 301 Location "https://[HTTP::host][HTTP::uri]"
}

when HTTP_RESPONSE {
	#HSTS
	HTTP::header insert Strict-Transport-Security "max-age=$static::max_age; includeSubDomains"
	#HPKP
	HTTP::header insert Public-Key-Pins "pin-sha256=\"$static::fqdn_pin\" max-age=$static::max_age; includeSubDomains"
	#X-XSS-Protection
	HTTP::header insert X-XSS-Protection "1; mode=block"
	#X-Frame-Options
	HTTP::header insert X-Frame-Options "DENY"
	#X-Content-Type-Options
	HTTP::header insert X-Content-Type-Options "nosniff"
	#CSP
	HTTP::header insert Content-Security-Policy "default-src https:"
	#CSP for IE
	HTTP::header insert X-Content-Security-Policy "default-src https:"
}
