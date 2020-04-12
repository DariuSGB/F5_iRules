#########################################################################
# title: LB_2Pools.tcl                                                  #
# author: Dario Garrido                                                 #
# date: 20200409                                                        #
# description: iRule for loadbalancing between 2 different pools        #
#########################################################################

when CLIENT_ACCEPTED {
	# Take the last pool selection
	set selection [table lookup -subtable "[virtual name]" pool_selection]
	# Eval pool selection
	if { [active_members <A_POOL_NAME>] == 0 } {
		set selection "<B_POOL_NAME>"
		table replace -subtable "[virtual name]" pool_selection $selection
	} elseif { [active_members <B_POOL_NAME>] == 0 } {
		set selection "<A_POOL_NAME>"
		table replace -subtable "[virtual name]" pool_selection $selection
	}
	# Apply pool selection
	switch $selection {
		"<A_POOL_NAME>" {
			pool <A_POOL_NAME>
		}
		"<B_POOL_NAME>" {
			pool <B_POOL_NAME>
		}
		default {
			pool <A_POOL_NAME>
			table set -subtable "[virtual name]" pool_selection <A_POOL_NAME> indefinite indefinite
		}
	}
}
