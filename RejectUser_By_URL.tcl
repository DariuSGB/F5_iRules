#########################################################################
# title: RejectUser_By_URL.tcl                                          #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for blocking user acces by URL                     #
#########################################################################

when HTTP_REQUEST {
	if { [class match [string tolower [HTTP::uri] ] contains DG_URL_List ] } { 
		HTTP::respond 200 content "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br><a href='javascript:history.back();'>\[Go Back\]</a></body></html>" noserver Connection close
	}
}
