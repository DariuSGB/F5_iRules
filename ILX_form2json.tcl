#########################################################################
# title: ILX_form2json.tcl                                              #
# author: Dario Garrido                                                 #
# date: 20200505                                                        #
# description: iRule for executing ILX plugin 'form2json_pl'            #
#########################################################################

when HTTP_REQUEST {
	# Set initial variables
    set arg "foo=bar&abc=xyz&abc=123"
    set timeout "1000"
    # Execute RPC call
    set handle [ILX::init form2json_pl form2json_ext]
    if { [catch {ILX::call $handle -timeout $timeout form2json $timeout $arg} result] } {
        log local0.  "ERROR: RPC call error"
        return
    }
    # Check RPC output
    if {[lindex $result 0] > 0} {
        switch [lindex $result 0] {
            1 { set error_msg "Error initializating variables"}
            2 { set error_msg "Error parsing POST form"}
            3 { set error_msg "Error translating to JSON"}
        }
        log local0. "ERROR: $error_msg"
    } else {
        set json [lindex $result 1]
        log local0. "JSON: $json"
    }
}
