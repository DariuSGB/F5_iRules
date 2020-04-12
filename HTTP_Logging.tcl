#########################################################################
# title: HTTP_Logging.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for logging HTTP requests                          #
#########################################################################

when HTTP_REQUEST {
	set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
	log local0. "============================================="
	log local0. "$LogString (request) - request: [HTTP::method]"
	foreach aHeader [HTTP::header names] {
		log local0. "$aHeader: [HTTP::header value $aHeader]"
	}
	log local0. "============================================="
}
when HTTP_RESPONSE {
	log local0. "============================================="
	log local0. "$LogString (response) - status: [HTTP::status]"
	foreach aHeader [HTTP::header names] {
		log local0. "$aHeader: [HTTP::header value $aHeader]"
	}
	log local0. "============================================="   
}
