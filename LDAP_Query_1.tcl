#########################################################################
# title: LDAP_Query_1.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20200426                                                        #
# description: iRule for executing a LDAP query (using APM)             #
# usage: GET <scheme>://<virtual>/lookup/<username>                     #
# requires: Access policy created and installed in the virtual server   #
# ---------    --------------    --------                               #
# | Start | -> | LDAP_Query | -> | Deny |                               #
# ---------    --------------    --------                               #
# LDAP Query:                                                           #
# |- Server: /Common/LDAP-DC                                            #
# |- SearchDN: cn=users,dc=springfield,dc=com                           #
# |- SearchFilter: (cn=%{session.ldap.username})                        #
#########################################################################

# REF - https://clouddocs.f5.com/api/irules/Query-LDAP-From-An-iRule-And-Or-Use-APM-With-Non-HTTP-Services.html

when HTTP_REQUEST {
	# Enable Clientless-mode
	HTTP::header insert "clientless-mode" 1
	# Get username from URI
	set username ""
	set path [string trim [string tolower [HTTP::path]] /]
	if { $path starts_with "lookup/" } {
		set username [getfield $path "/" 2]
	}
}
when ACCESS_SESSION_STARTED {
	# Assign username to APM ldap-query variable
	if {$username ne ""} {
		ACCESS::session data set session.ldap.username $username
	}
}
when ACCESS_POLICY_COMPLETED {
	set reply "NOT_FOUND"
	if {[ACCESS::session data get session.ldap.last.queryresult] == 1} {
		set reply [ACCESS::session data get session.ldap.last.attr.memberOf]
	}
	# Reply to the client with LDAP response
	ACCESS::respond 200 content $reply Content-Type "text/plain" Connection close
	# Delete current session
	ACCESS::session remove -sid [ACCESS::session sid]
}
