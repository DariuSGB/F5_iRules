#########################################################################
# title: RejectUser_By_IP.tcl                                           #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for blocking user acces by client IP               #
#########################################################################

when HTTP_REQUEST {
	if { [class match [IP::client_addr] equals DG_Client_IP ] } { 
		HTTP::respond 200 content "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br><a href='javascript:history.back();'>\[Go Back\]</a></body></html>" noserver Connection close
	}
}
