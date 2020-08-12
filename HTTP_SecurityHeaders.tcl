#########################################################################
# title: HTTP_SecurityHeaders.tcl                                       #
# author: Dario Garrido                                                 #
# date: 20200811                                                        #
# description: iRule for adding HTTP security headers                   #
#########################################################################

when RULE_INIT {
	#set static::fqdn_pin1 "EhWYeGvikvmcBCXY97kSFqziYxyIHtYd4cTrC3HX/ag="    ;# openssl x509 -pubkey < tls.crt | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
	#set static::fqdn_pin2 "MHJYVThihUrJcxW6wcqyOISTXIsInsdj3xK8QrZbHec="    ;# openssl req -pubkey < csr.csr | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
	set static::max_age 604800                                              ;# 7 days
}

when HTTP_REQUEST {
	HTTP::respond 301 Location "https://[HTTP::host][HTTP::uri]"
}

when HTTP_RESPONSE {
	#HSTS
	HTTP::header insert Strict-Transport-Security "max-age=$static::max_age; includeSubDomains"
	#HPKP (Deprecated)
	#HTTP::header insert Public-Key-Pins "pin-sha256=\"$static::fqdn_pin1\"; pin-sha256=\"$static::fqdn_pin2\"; max-age=$static::max_age; includeSubDomains"
	#Expect-CT
	HTTP::header insert Expect-CT "enforce, max-age=$static::max_age"
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
