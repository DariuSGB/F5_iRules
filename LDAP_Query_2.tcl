#########################################################################
# title: LDAP_Query_2.tcl                                               #
# author: Dario Garrido                                                 #
# date: 20200426                                                        #
# description: iRule for executing a LDAP query (using APM)             #
# usage: GET <scheme>://<virtual>/lookup/<username>                     #
# requires: Access policy created                                       #
# ---------    --------------    --------                               #
# | Start | -> | LDAP_Query | -> | Deny |                               #
# ---------    --------------    --------                               #
# LDAP Query:                                                           #
# |- Server: /Common/LDAP-DC                                            #
# |- SearchDN: cn=users,dc=springfield,dc=com                           #
# |- SearchFilter: (cn=%{session.ldap.username})                        #
#########################################################################

# REF - https://clouddocs.f5.com/api/irules/ACCESS__policy.html

when CLIENT_ACCEPTED {
    # Create access policy session
    set flow_sid [ACCESS::session create -timeout 5 -lifetime 5]
}
when HTTP_REQUEST {
    # Get username from URI
    set username ""
    set path [string trim [string tolower [HTTP::path]] /]
    if { $path starts_with "lookup/" } {
        set username [getfield $path "/" 2]
    }
    # Evaluate access policy "A-LDAP-Query"
    if {$username ne ""} {
        ACCESS::policy evaluate -sid $flow_sid -profile /Common/A-LDAP-Query session.ldap.username $username session.server.landinguri [string tolower [HTTP::uri]]
    }
    # Capture LDAP Query Response
    set reply "NOT_FOUND"
    if {[ACCESS::session data get -sid $flow_sid session.ldap.last.queryresult] == 1} {
        set reply [ACCESS::session data get -sid $flow_sid session.ldap.last.attr.memberOf]
    }
    # Reply to the client with "memberOf" content
    HTTP::respond 200 content "<html><body>$reply</body></html>" noserver Connection close
    # Delete access policy session
    ACCESS::session remove -sid $flow_sid
    # There is a bug that avoids to remove APM sessions
    # REF - https://cdn.f5.com/product/bugtracker/ID697590.html
    # workaround: Modify timeout value
    ACCESS::session modify -sid $flow_sid -timeout 1
}
