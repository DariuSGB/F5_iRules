#########################################################################
# title: ECA_NTLM_Auth.tcl                                              #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for NTLM Auth                                      #
# https://support.f5.com/csp/article/K03010204                          #
#########################################################################

when HTTP_REQUEST {
	if { [ACCESS::session data get session.ntlm.last.result] eq 1 } {
		ECA::disable
	} else {
		ECA::enable
		ECA::select select_ntlm:/Common/ntlm_config
	}
}
