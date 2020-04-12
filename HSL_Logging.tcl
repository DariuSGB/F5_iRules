#########################################################################
# title: HSL_Logging.tcl                                                #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for High Speed Logging                             #
#########################################################################

when SERVER_CONNECTED {
	set timestamp  [clock clicks -milliseconds]
	set cs_client_ip [clientside {IP::remote_addr}]
	set cs_client_port [clientside {TCP::remote_port}]
	set cs_server_ip [clientside {IP::local_addr}]
	set cs_server_port [clientside {TCP::local_port}]
	set ss_client_ip [serverside {IP::local_addr}]
	set ss_client_port [serverside {TCP::local_port}]    
	set ss_server_ip [serverside {IP::remote_addr}]
	set ss_server_port [serverside {TCP::remote_port}]
	catch {
		set hsl [HSL::open -publisher /Common/HSL_Pub]
		HSL::send $hsl "{\"version\":\"1.1\",\"level\":\"6\",\"_stream_filter\":\"<STREAM_FILTER>\",\"_TIMESTAMP\":\"[clock clicks -milliseconds]\",\"_CLIENT\":\"[clientside {IP::remote_addr}]:[clientside {TCP::remote_port}]\",\"_VIP\":\"[clientside {IP::local_addr}]:[clientside {TCP::local_port}]\",\"_SNAT\":\"[serverside {IP::local_addr}]:[serverside {TCP::local_port}] \",\"_SERVER\":\"[serverside {IP::remote_addr}]:[serverside {TCP::remote_port}]\"}"
	}
}
