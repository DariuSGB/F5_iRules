##################################################################################
# title: Table_Api.tcl                                                           #
# author: Dario Garrido                                                          #
# date: 20200425                                                                 #
# description: iRule for managing subtables using API REST                       #
# usage:                                                                         #
# |- GET /apitable/table/ - Get all information table                            #
# |- GET /apitable/table/key/ - Get key value for specified table                #
# |- POST /apitable/table/key/ - Create a new key-value pair for specified table #
# |- PUT /apitable/table/key/ - Modify a key-value for specified table           #
# |- DELETE /apitable/table/key/ - Delete key-value pair for specified table     #
# |- DELETE /apitable/table/ - Delete all table information                      #
# https://devcentral.f5.com/s/articles/restful-access-to-big-ip-subtables        #
##################################################################################

when HTTP_REQUEST {
	# Capture URI with '/' in the edges
	set api_uri [string trim [string tolower [HTTP::uri]] /]
	# Take first field (application name)
	set api_app [getfield $api_uri "/" 1];
	if { $api_app == "apitable" } {
		# Create an array of fields with the URI
		set uri_fields [split $api_uri "/"]
		# Assign variables by fields
		switch [llength $uri_fields] {
			2 { set tname [lindex $uri_fields 1] }
			3 { scan [lrange $uri_fields 1 end] %s%s tname key }
			4 { scan [lrange $uri_fields 1 end] %s%s%s tname key val }
			default {
				HTTP::respond 200 content "<HTML><BODY>Invalid number of arguments</BODY></HTML>"
				return
			}
		}
		# Select action by HTTP method
		switch [HTTP::method] {
			"GET" {
			# GET /apitable/table/ - Get all information table
			# GET /apitable/table/key/ - Get key value for specified table
				if { [info exists tname] && [info exists key] && not [info exists val] } {
					set kvpair "[table lookup -notouch -subtable $tname $key]"
					if { $kvpair != "" } { HTTP::respond 200 content "<HTML><BODY>$key:$kvpair</BODY></HTML>" }
					else { HTTP::respond 200 content "<HTML><BODY>Empty value</BODY></HTML>" }
				} elseif { [info exists tname] && not [info exists key] && not [info exists val] } {
					set keys [table keys -subtable $tname]
					if { $keys != "" } {
						foreach tkey [table keys -subtable $tname] {
							lappend kvpair "$tkey:[table lookup -notouch -subtable $tname $tkey]"
						}
						HTTP::respond 200 content "<HTML><BODY>$kvpair</BODY></HTML>"
					} else { HTTP::respond 200 content "<HTML><BODY>Empty table</BODY></HTML>" }
				} else {
					HTTP::respond 200 content "<HTML><BODY>Error!  Must supply /table/key/ or /table/</BODY></HTML>"
				}
			}
			"POST" {
			# POST /apitable/table/key/ - Create a new key-value pair for specified table
				if { [info exists tname] && [info exists key] && [info exists val] } {
					table add -subtable $tname $key $val indefinite indefinite
					HTTP::respond 200 content "<HTML><BODY>SUCCESS</BODY></HTML>"
				} else { HTTP::respond 200 content "<HTML><BODY>Error!  Must supply /table/key/value/</BODY></HTML>" }
			}
			"PUT" {
			# PUT /apitable/table/key/ - Modify a key-value for specified table
				if { [info exists tname] && [info exists key] && [info exists val] } {
					if { [table replace -subtable $tname $key $val indefinite indefinite] != "" } {
						HTTP::respond 200 content "<HTML><BODY>SUCCESS</BODY></HTML>"
					} else { HTTP::respond 200 content "<HTML><BODY>Table and/or Key information doesn't exist</BODY></HTML>" }
				} else { HTTP::respond 200 content "<HTML><BODY>Error!  Must supply /table/key/value/</BODY></HTML>" }
			}
			"DELETE" {
			# DELETE /apitable/table/key/ - Delete key-value pair for specified table
			# DELETE /apitable/table/ - Delete all table information
				if { [info exists tname] && [info exists key] } {
					table delete -subtable $tname $key
					HTTP::respond 200 content "<HTML><BODY>SUCCESS</BODY></HTML>"
				} elseif { [info exists tname] } {
					table delete -subtable $tname -all
					HTTP::respond 200 content "<HTML><BODY>SUCCESS</BODY></HTML>"
				} else { HTTP::respond 200 content "<HTML><BODY>Error! Must supply /table/key/ or /table/</BODY></HTML>" }
			}
			default { HTTP::respond 200 content "<HTML><BODY>Not a valid method for this interface</BODY></HTML>" }
		}
	}
}
