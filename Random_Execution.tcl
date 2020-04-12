#########################################################################
# title: Random_Execution.tcl                                           #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for executing events randomly                      #
#########################################################################

when HTTP_REQUEST {
	if { rand() > 0.1 } {
		return
	}
	log local0. "HTTP_REQUEST EXECUTION (90% OF TIMES)"
}
