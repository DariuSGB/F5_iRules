#########################################################################
# title: Rewriting_Correction.tcl                                       #
# author: Dario Garrido                                                 #
# date: 20201016                                                        #
# description: Correct errors during rewriting process                  #
# rules:                                                                #
# >> REPLACE: http:? -> javascript:?                                    #
# >> REPLACE: https:? -> javascript:?                                   #
# >> NOT REPLACE: http:/ -> http:/                                      #
# >> NOT REPLACE: https:/ -> https:/                                    #
#########################################################################

when REWRITE_REQUEST_DONE {
	if { [HTTP::uri] ends_with "/" } {
		REWRITE::post_process 1
	}
}

when REWRITE_RESPONSE_DONE {
	# Define expressions
	set find "https?:\[^/\]"
	set fixed_chars 1  ;# represents those chars that should not be replace in the matching expression
	set replace "javascript:"
	
	# Get indexes
	set indices [regexp -all -indices -inline $find [REWRITE::payload]]
		
	# Make replacement of matching expressions
	set offset 0
	foreach idx $indices {
		set start [ expr { [lindex $idx 0] + $offset } ]
		set end [expr { [lindex $idx 1] - $fixed_chars + $offset } ]
		set len [expr { $end - $start + 1 } ]
		REWRITE::payload replace $start $len $replace
		set diff [expr { [string length $replace] - $len } ]
		incr offset $diff
	}
}
