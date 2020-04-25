#########################################################################
# title: SideBand_Connection.tcl                                        #
# author: Dario Garrido                                                 #
# date: 20200425                                                        #
# description: iRule with an example of HSSR usage (see HSSR.tcl)       #
#########################################################################

when HTTP_REQUEST {
    # Set initial variables
    set virtual /Common/VS-INTWEB50_80
    set uri "http://10.130.40.50/apitable/test/name"
    set initial_str "<BODY>"
    set final_str "</BODY>"
    
    # Execute HTTP Super SideBand Requestor
    set status [call /Common/HSSR::http_req -virt $virtual -uri $uri -method GET -rbody rbody]
    if {($status == 200) && ($rbody ne "")} {
        set body [findstr $rbody $initial_str [string length $initial_str] $final_str]
        set key [getfield $body ":" 1];
        set value [getfield $body ":" 2];
        HTTP::respond 200 content "{$key:$value}"
    }
}
