#########################################################################
# title: HSSR.tcl                                                       #
# author: Mark Seecof                                                   #
# date: 20200425                                                        #
# description: iRule for executing HTTP SideBand Requests               #
# usage: Save this iRule in Common partition with name "HSSR"           #
#########################################################################

# REF - https://clouddocs.f5.com/api/irules/HTTP-Super-SIDEBAND-Requestor-Client-Handles-Redirects-Cookies-Chunked-Transfer-APM-Access-etc.html
# REF - https://clouddocs.f5.com/api/irules/SIDEBAND.html

#== Mark's HTTP Super SIDEBAND Requestor! (v2.1) =====================
#
# Save THIS iRule in the Common partition under the name 'HSSR'.  Other
# iRules will "call" procs (mainly 'http_req') from /Common/HSSR, e.g.,
# "set status [call /Common/HSSR::http_req -uri $someURL -state xyz]"
# and "call /Common/HSSR::http_done -state xyz".
#
# Also install iRule /Common/HSSR-helper (see below) for when you want to
# connect to a TLS-protected (https) service.
#
#  ////////////////////////////////////////////////////////////////////////
# // Follow SOL12224 to avert issues resolving hostnames in URI's after //
# \\ you set System:Configuration:Device:DNS:BIND_Forwarder_Server_List \\
#  \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Changes from previous version:  iRules proc implementation; persistent-
# connection support; full/proper cookie support; IPv6 support; universal
# outbound HTTP(S) helper-virtual-server support (including SNI); easy
# HTML form submission; HTTP proxy support; HTTP 100-Continue support for
# Web Services; good RFC compliance; content character-set sniffing; much
# more besides!
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
# This iRule implements a nifty HTTP client 'http_req' using SIDEBAND.
# It handles challenges like redirects and cookies (lets you access APM-
# protected services!), IPv6, chunked transfer coding, easy HTML forms,
# and Basic AuthN.
#
# You may connect directly to remote HTTP servers or to virtual servers
# (http/https) on your LTM.  To connect to HTTPS remote servers you must
# utilize a simple helper virtual server with a Server SSL Profile.  For
# universal outbound HTTP(S) support attach the iRule 'HSSR-helper' to
# your helper virtual server.  See 'HSSR-helper' for easy setup details.
#
# Basic usage example:
#  set sts [call /Common/HSSR::http_req -uri "https://foo.com/bar/" \
#                                       -virt /Common/vs-HSSR-helper \
#                                       -tag "get-bar" -rbody rbody]
#  log local0.info "server returned status=${sts}, content=${rbody}"
#
# NOTE: values for "-(state|rbody|rheaders|rcookies|rformat) pqr" NAME
# VARIABLES $pqr INTO WHICH DATA WILL BE PLACED, destroying any previous
# contents!
#
# Return value from http_req is HTTP status code ('555' indicates some
# local problem--check the LTM log).  You may give options in any order
# but if you repeat an option the later value replaces the earlier.
#
# You supply:
#  -uri = absolute URI of target (required!)
#
#  -virt = (optional) name of LTM virtual server to connect to--if set,
#            used in lieu of host:port from -uri (or host:port from
#            -proxy url).  -virt value will be reused from -state info
#            (see below) until you give -virt option again.  To stop using
#            -virt specify "-virt {}".  Note: use of -virt is required to
#            make https requests, and is useful when accessing a resource
#            represented by a virtual server on your BIG-IP.
#
# Even when you set -virt, your -uri URI must include some hostname or
# IP address (which by default will be copied into the HTTP Host header).
# If you do not set -virt, then:  ensure your BIG-IP DNS setup is valid
# so [RESOLV::lookup] works; or supply the -ns option; or put server IP
# (or IP:port) in -uri URI.  If you put server IP into URI you may use
# the -host option to force a hostname (rather than numeric IP) into the
# HTTP Host header (plus TLS SNI when using 'HSSR-helper').  To make
# https requests you must use "-virt /Common/vs-HSSR-helper" or similar.
# Attach the iRule 'HSSR-helper' to your helper-virtual-server.
#
# IMPORTANT:  If you will make multiple requests, either to a single
# server or to various servers which use cookies, PLEASE supply:
#
#  -state = name of variable in which connection state (including cookies,
#             credentials, custom headers, -virt value, -proxy value, and
#             -ns value) will be stored between calls to http_req.  In use
#             this looks like "-state xyz" (no '$' before "xyz").  Using
#             -state lets http_req perform better by keeping a SIDEBAND
#             connection open between requests when appropriate.  Storing
#             cookies also improves performance in most cases.  If using
#             "-state xyz" you may "call /Common/HSSR::http_close xyz"
#             after your final call to http_req.  NOTE:  preserve the
#             value of $xyz between calls to http_req.  Default:  none
#             (stateless operation).
#
# You should supply as well:
#  -tag = a short name for target (e.g., hostname) just for local logging.
#  -key = a short ID for this particular request in the local log, such
#          as [ACCESS::session data get session.user.display_sessionid].
#          Default is client address:port if available.
#
# To receive data from the target server into variables, indicate:
#
#  -rbody = name (without '$') of variable to receive (final) response
#             entity body.  -rbody value will be a TCL string in either
#             binary or Unicode-text format (perhaps transcoded, in the
#             latter case, from text in another charset like ISO-8859-1);
#             see -rformat value to find out which!  (This is mandated by
#             the way iRules TCL strings work.  See -rformat and -sniff
#             options plus [Note 1] for more details.)
#  -rformat = name of variable which will be set to "binary" or "text" to
#               indicate format of -rbody value.  May be used without
#               -rbody option.
#
#  -rheaders = name of variable to receive (final) reply headers.  A fake
#                header 'X-HSSR-Charset' will be appended to indicate what
#                charset (if any) http_req thinks was used to encode the
#                response entity body (see the -sniff option).
#
#  -rcookies = name of variable to receive final summary of cookies (just
#                cookie names and values, so beware of duplicate names).
#
#  -maxbody = longest acceptable response body (octets).  Default 1 Mbyte.
#               Before increasing -maxbody length-limit review SOL6578.
#
# Each of -(rbody|rheaders|rcookies|rformat) is optional and -(rheaders|
# rcookies) variables, if requested, will be lists of alternating names
# and values.
#
# For speed, http_req only sniffs content-type when one or more of
# options -(rbody|rheaders|rformat) are specified.
#
# You may optionally supply the following (use only ASCII characters in
# values of options other than -body and -form):
#
#  -method = [GET|POST|...], default is GET.
#
#  -form = a TCL list of (alternating) form-field names and values to
#            submit to -uri, like [list "name" "homer" "food" "doughnut"].
#            After conversion to 'application/x-www-form-urlencoded'
#            format the form-field data is appended to URI if -method is
#            GET or HEAD, uploaded in request body otherwise.  (With GET
#            or HEAD, -form yields standard query-string format like
#            "http://svc.example.com/whatever?name=homer&food=doughnut".)
#            Values must be text.  A suitable Content-Type header will be
#            sent. You may not use -form and -(body|type) at the same
#            time. Default: none.
#  -body = data to send (e.g., when method is POST). Default: none (but
#            see -form option).
#  -type = value of Content-Type header to send with -body data, such as
#            "application/json; charset=utf-8" or "multipart/form-data".
#            It is very important to set -type when sending -body data!
#            Default: none.
#  -headers = list of alternating HTTP header names and values to add to
#               request, such as {Accept text/* Accept-Language fr-CA}.
#               These headers override any corresponding defaults except
#               Host and Content-(Type|Length).  Defaults: {Accept */*
#               Accept-Language en User-Agent {BigIP/nn.xxxx (HSSRv2)}
#               Accept-Charset {utf-8;q=1, iso-8859-1;q=0.9, *;q=0.8}
#               Accept-Encoding identity} where nn.xxxx is TMOS version+
#               build-identifier and (HSSRv2) is version string for HTTP
#               Super SIDEBAND Requestor.  Headers set using -headers will
#               be reused from -state info until you set -headers again.
#               To cancel all custom headers give option "-headers [list]".
#
#  -cookies = list of alternating cookie names and values to inject into
#               request.  Default: none.  (To accumulate cookies between
#               calls to http_req use the -state option.  DO NOT copy
#               -rcookies value to -cookies.)
#
#  -userid = a username for Basic Authentication (default none) and...
#  -passwd = ...a password (missing -passwd defaults to empty string)
#             NB: to gain speed in the normal case, these credentials
#             will be sent preemptively and promiscuously to all servers
#             queried (even after redirection).  Credentials will be
#             reused from -state info until you supply -(userid|passwd)
#             again.  To clear credentials give option "-userid {}".
#
#  -nocache = [false|true] where *false*=trust upstream caches to do their
#               jobs; true=demand fresh responses from origin servers.
#               Default: false.  Note:  "-nocache true" may cause delays.
#               Also, http_req does not cache content locally--if you need
#               a cache, use a helper virtual server with a cache profile.
#
#  -ns = IP of DNS nameserver or name (e.g., /Common/vs-dns) of a virtual
#          server having a pool of nameservers to resolve hostnames in
#          URI's to IP addresses.  Default: none; use LTM nameserver(s).
#          Value of -ns will be reused from -state info until you give
#          -ns option again.  To stop using a custom nameserver supply
#          "-ns {}".
#
#  -hostname = (optional) hostname to place in HTTP Host header rather
#                than IP address or hostname from -uri URI.
#
# To utilize an HTTP(S) proxy server, supply:
#  -proxy = URL of HTTP proxy (like "https://proxy.example.com:8443/") to
#             use for BOTH http and https requests.  To access the proxy
#             itself via TLS you will need a helper virtual server (e.g.,
#             "-virt /Common/vs-HSSR-helper").  If you access a proxy
#             via plain http you may omit -virt but your traffic will NOT
#             be secure en-route to proxy.  If proxy wants authentication
#             (Basic AuthN only) place user-ID and password into proxy URL
#             like this: "https://userid:password@proxy.example.com/".
#             Default: none.  The value of -proxy will be reused from
#             -state info until you give -proxy option again.  To stop
#             using any proxy supply "-proxy {}".
#
# In special cases you may wish to supply:
#  -redir = [0|1|2] where 0=don't follow redirects; *1*=follow redirects
#             and retry POST/PUT/?? after any redir out-and-back (supports
#             POST to an APM-protected resource) but if -virt is set send
#             all requests to it; 2=like 1 except do not retry POST/etc.
#             Default is 1.
#
#  -expect = [0|100] where *0*=send -(body|form) data with request headers;
#              100=send request headers then wait for server prompt before
#              sending content.  (Used with WS+SOAP).  Default is 0.
#
#  -sniff = [0|1|2|3|4|5] where 0=determine content charset strictly per
#             rfc2616 so text defaults to ISO-8859-1; 1=like 0 but text
#             defaults to UTF-8; *2*=when charset is not set by rfc2616
#             header, determine charset heuristically (W3C method--best);
#             3=treat response as ISO-8859-1 text regardless of headers or
#             other info; 4=treat response as UTF-8 text regardless;
#             5=treat response as binary no matter what.  Default 2. [See
#             Note 1]  You may use -rheaders option and inspect value of
#             "X-HSSR-Charset" to learn http_req's charset determination
#             (likely easier than parsing reply headers and body yourself).
#
#  -munch = [0|1] where 0=enforce cookie origin rules; *1*=accept and send
#             cookies liberally when hostname in -uri is not FQDN (helpful
#             when you access some resource with just IP or a short alias
#             for host in -uri, perhaps by using -virt).  Default is 1.
#
#  -timeout = maximum wait for connection in milliseconds.  Default 7500.
#  -wait = maximum wait for server response in seconds.  Default 10.  The
#            receive-polling interval is proportional to -wait.  Note:  to
#            fetch a very large response you may have to increase -wait.
#  -idle = maximum idle time on connection in seconds.  Default 300.
#  -maxtime = number of seconds after which http_req will cease trying to
#               complete request and just return the current status.  Use
#               this option to limit "tolerance stacking" whereby a series
#               of redirects and other delays, each of which seems
#               tolerable by itself, may sum to an intolerable delay.
#               Default is roughly 4-1/2 minutes using default -wait and
#               -timeout values.  Note:  setting -maxtime isn't mandatory;
#               http_req always terminates even if server is malicious.
#               [See Note 2]
#  -debug = [0|1] where 1 means log debug info.  Default is 0.
#
# [Note 1] The format (binary or text (=Unicode), see -rformat option)
#  of -rbody value depends on content-mimetype as well as charset.  FOR
#  TEXTUAL CONTENT-TYPES (explicit or sniffed), IF charset is NOT
#  recognized as one which iRules can transcode to Unicode, THEN -rbody
#  value will be a BINARY string.  IF charset CAN be transcoded to
#  Unicode, THEN -rbody value WILL BE a UNICODE string NO MATTER WHAT ANY
#  HEADERS SAY.  (For non-text content like image/jpeg, -rbody format
#  will be binary, of course.)  The X-HSSR-Charset (fake) header shows
#  approximately what the original character set was (ASCII and
#  Windows-1252 map to ISO-8859-1).  (Note:  If you control the remote
#  server, make it send a Content-Type header with suitable charset=XXX
#  on every response!)  IF your server does NOT indicate charset BUT you
#  are CERTAIN it is ALWAYS the same for text/* mimetypes, you may set
#  -sniff [0|1] to save a few cycles.  You may use -sniff [3|4|5] when
#  you are very confident of response format.  (Without charset info
#  in headers "-sniff 2" may mistake other ISO-8859-* charsets for
#  ISO-8859-1; they are very hard to distinguish).
#
# [Note 2] Do not write to me about the Halting Problem.
#
# SECURITY NOTES:  for performance reasons this code sends Basic AuthN
# credentials promiscuously.  Also this code does NOT validate all inputs
# strictly, nor will it prevent a malicious server wasting some BIG-IP
# memory.  Do not expect this code to protect correspondent systems; for
# example, this code will accept and repeat cookies with invalid (per
# rfc6265) and probably dangerous names.  NB: if you supply bogus options
# this code may produce unsought results.
#
# Copyright &copr; 2014 Mark Seecof.  Permission to modify and distribute
# granted gratis on condition that you include this notice with each copy.
#

when RULE_INIT {
 #IPv6 hostname per rfc2732; we recognize IPv6 but don't validate strictly
 set static::HSSR_urlsplit {(?i)^(https?)://(?:([^:@]+):?([^@]*)@)?((?:\x5b[0-9a-f:.]{2,45}(?:%[0-9a-z:.]{1,18})?\x5d)|(?:[0-9.a-z-]{1,255}))(?::([0-9]{0,5}))?([*]|(?:/[^\x23]*)?)(?:\x23.*|)$}

 set static::HSSR_ipv6match {(?i)[\x5b]?([0-9a-f:.]{2,45}(?:%[0-9a-z:.]{1,18})?)[\x5d]?}

 set static::HSSR_ckymatch {^([^=\x24\x5c\x7b\x7d\x20\t]+)="?([^\x22;,\x20\t\x5c]*)"?(?:[\x20\t]*;[\x20\t]*(.*))?$}

 set static::HSSR_quiver {(?i)<meta[\x20\t][^>]*[\x20\t]?http-equiv=['\x22]?content-type['\x22\x20\t]?[^>]*>}

 set static::HSSR_csetmeta {(?i)<meta[\x20\t]+charset=['\x22]?([^'\x22>]+)}

 set static::HSSR_xmlenc {(?i)<[?]xml[\x20\t]+.*encoding=['\x22]?([^'\x22?>]+)}

 #string option names (sort alphabetically)
 set static::HSSR_s_opts [list body cookies form headers hostname key \
                     method nocache ns passwd proxy rbody rcookies \
                     rformat rheaders state tag type uri userid virt]
 #integer options (sort these too)
 set static::HSSR_n_opts [list debug expect idle maxbody maxtime munch \
                     redir sniff timeout wait]
 #and these as well...
 set static::HSSR_done [list accept accept-charset accept-encoding \
                   accept-language content-length content-type host \
                   user-agent x-hssr-helper]
 set static::HSSR_nogo [list closed closing failed timeout]
}

proc http_req {args} {
 #set me [lindex [info level 0] 0]
 #oops, in TMOS 11.4-5 [info level 0] unavailing and [info frame] undefined
 set me "http_req"

 set uri ""
 set virt "!"
 set hostname ""
 set state ""
 set tag "HSSR"
 set key ""
 set rbody ""
 set rformat ""
 set rheaders ""
 set rcookies ""
 set method "GET"
 set form [list]
 set body ""
 set type ""
 set headers [list "!" "!"]
 set cookies [list]
 set userid "\x19"
 set passwd ""
 set proxy "!"
 set ns "!"

 set expect 0
 set nocache false
 set sniff 2
 set redir 1
 set munch 1
 set timeout 7500
 set wait 10
 set idle 300
 set maxtime 0
 set maxbody 1048576
 set debug 0

 set e ""
 set visits 0
 while {[incr visits] < 2} {
  if {[llength $args] & 1} {
   set e "arguments must be '-option value' pairs"
  } else {
   foreach {n v} $args {
    set opt [string range $n 1 end]
    set xn -1
    if {!($n starts_with "-") ||
        ( ([lsearch -sorted $static::HSSR_s_opts $opt] < 0) &&
          ([set xn [lsearch -sorted $static::HSSR_n_opts $opt]] < 0) )} {
     set e "option '${n}' not recognized"
     break
    }
    if {($xn >= 0) && [regexp {[^0-9]} $v]} {
     set e "option ${n} value must be integer"
     break
    }
    set $opt $v
   }
  }

  #evade iRules checker so we can be called from events
  #on different kinds of virtual server, etc
  if {($key eq "") &&
      ![catch {eval "IP::client_addr"} key] &&
      ![catch {eval "IP::protocol"} pn] &&
      ([set qry [expr {($pn == 6) ? "TCP::client_port" :
                        (($pn == 17) ? "UDP::client_port" : "")}]] ne "") &&
      ![catch {eval $qry} tmp]} {
   append key ":" $tmp
  }
  set tkm "${tag} ${key}: ${me}"

  if {$e ne ""} { break }

  #saved state (possibly reuse connection)?
  if {$state ne ""} { upvar 1 $state stvar }
  if {![info exists stvar] || ([llength $stvar] < 9)} {
   set stvar [list false {} "" "" "" "" [list] "" ""]
  } elseif {$debug && [lindex $stvar 0]} {
   log local0.info "${tkm} might re-use conn to [lindex $stvar 2]"
  }
  foreach {connected conn cdest vs px nsvr crumbs creds kopf} $stvar { break }

  if {$virt eq "!"} { set virt $vs }
  if {$proxy eq "!"} { set proxy $px }
  if {$ns ne "!"} { set nsvr [expr {($ns ne "") ? "@${ns}" : ""}] }

  set ffcount [llength $form]
  set bodylen [string bytelength $body]

  set auth_hdrs ""

  if {$uri eq ""} {
   set e "you must supply -uri option!"
  } elseif {![regexp $static::HSSR_urlsplit $uri junk schm ruid rpwd host port path] ||
            ([string length $path] > 2040)} {
   set e "malformed -uri ${uri}"
  } elseif {([set schm [string tolower $schm]] ne "") &&
            [set rTLS [expr {[string index $schm end] eq "s"}]] &&
            ($virt eq "")} {
   set e "SIDEBAND to TLS (https) needs helper virtual-server"
  } elseif {$ffcount & 0x1} {
   set e "-form value must list pairs of field names and values"
  } elseif {$ffcount && ($bodylen || ($type ne ""))} {
   set e "option -form precludes options -body or -type"
  } elseif {$bodylen && (($method eq "GET") || ($method eq "HEAD"))} {
   set e "option -body incompatible with -method ${method}"
  } elseif {($path eq "*") && ($method ne "OPTIONS")} {
   set e "URI path '*' valid only with -method OPTIONS"
  } elseif {$ruid ne ""} {
   set e "username+password in request URI not supported"
  } elseif {[llength $headers] & 1} {
   set e "-headers option invalid"
  } elseif {[llength $cookies] & 1} {
   set e "-cookies option invalid"
  } elseif {$expect && ( ($expect != 100) || !($bodylen || $ffcount) ||
                         ($method eq "GET") || ($method eq "HEAD") )} {
   set e "use '-expect 100' only when sending -body or -form data"
  } elseif {$proxy ne ""} {
   if {![regexp $static::HSSR_urlsplit $proxy junk pxy_s pxy_uid pxy_pwd pxy_h pxy_p]} {
    set e "-proxy URL invalid"
    break
   }
   set pxy_s [string tolower $pxy_s]
   set pxy_h [string tolower $pxy_h]
   if {[string index $pxy_h 0] eq "\x5b"} {
    set pxy_h [string map [list "%25" "%"] $pxy_h]
    regexp $static::HSSR_ipv6match $pxy_h junk raddr
   } else {
    if {[string index $pxy_h end] eq "."} {
     set pxy_h [string range $pxy_h 0 end-1]
    }
    if {![catch {IP::addr $pxy_h mask 255.255.255.255}]} {
     set raddr [eval format "::ffff:%02x%02x:%02x%02x" [split $pxy_h "."]]
    } else {
     if {!( ([set tmp [lindex [eval "RESOLV::lookup ${nsvr} inet -a ${pxy_h}"] 0]] ne "") &&
            ([set raddr [eval format "::ffff:%02x%02x:%02x%02x" [split $tmp "."]]] ne "")
          ) &&
         ([set raddr [lindex [eval "RESOLV::lookup ${nsvr} inet6 -aaaa ${pxy_h}"] 0]] eq "") &&
         ($virt eq "")} {
      set e "cannot resolve proxy host ${pxy_h} to IP address"
      break
     }
    }
   }
   if {$pxy_p eq ""} {
    set pxy_p [expr {([string index $pxy_s end] eq "s") ? "443" : "80"}]
   }
   set xhelper ""
   if {$virt eq ""} {
    set dest "${raddr}.${pxy_p}"
   } else {
    set dest $virt
    if {$raddr ne ""} {
     set xhelper "X-HSSR-Helper: [list $pxy_s $raddr $pxy_p [virtual] $key]\r\n"
    }
   }
   if {$pxy_uid ne ""} {
    append auth_hdrs "Proxy-Authorization: Basic\x20" \
                     [b64encode "${pxy_uid}:${pxy_pwd}"] "\r\n"
   }
   if {$debug} {
    log local0.info "${tkm} will send requests via proxy ${pxy_h}:${pxy_p}"
   }
  } else {
   set xhelper [set dest ""]
  }
 } ; #one-visit block
 if {$e ne ""} {
  log local0.err "${tkm} ${e}"
  return -code error "${me} ${e}"
 }

 set host [string tolower $host]
 if {[set ipv6 [expr {[string index $host 0] eq "\x5b"}]]} {
  set host [string map [list "%25" "%"] $host]
  regexp $static::HSSR_ipv6match $host junk haddr
 } elseif {[string index $host end] eq "."} {
  set host [string range $host 0 end-1]
 }
 if {$port eq ""} { set port [expr {$rTLS ? "443" : "80"}] }
 set server "${host}:${port}"

 if {$path eq ""} { set path "/" }

 #milk helps us swallow cookies
 set milk [expr {$munch && ![regexp {[^.][.][^.]+[^0-9\x5d]$} $host]}]

 if {$userid eq ""} {
  set creds ""
 } elseif {$userid ne "\x19"} {
  set creds "Authorization: Basic [b64encode "${userid}:${passwd}"]\r\n"
 }
 if {$creds ne ""} { append auth_hdrs $creds }

 #reuse headers like User-Agent from saved state unless caller overrides
 if {($kopf eq "") || ![llength $headers] ||
     ([lindex $headers 0] ne "!") || ([lindex $headers 1] ne "!")} {
  set kopf ""

  set v [expr {([set x [lsearch -regexp $headers {(?i)^Accept$}]] < 0) ? \
               "*/*" : [lindex $headers [incr x]]}]
  append kopf "Accept: ${v}\r\n"

  set v [expr {([set x [lsearch -regexp $headers {(?i)^Accept-Charset$}]] < 0) ? \
               "utf-8;q=1, iso-8859-1;q=0.8, *;q=0.6" : \
               [lindex $headers [incr x]]}]
  append kopf "Accept-Charset: ${v}\r\n"

  set v [expr {([set x [lsearch -regexp $headers {(?i)^Accept-Encoding$}]] < 0) ? \
               "identity" : [lindex $headers [incr x]]}]
  append kopf "Accept-Encoding: ${v}\r\n"

  set v [expr {([set x [lsearch -regexp $headers {(?i)^Accept-Language$}]] < 0) ? \
               "en" : [lindex $headers [incr x]]}]
  append kopf "Accept-Language: ${v}\r\n"

  upvar #0 tcl_platform static::tcl_platform ; #SOL14544 workaround
  set tmm_vers $static::tcl_platform(tmmVersion)
  set v [expr {([set x [lsearch -regexp $headers {(?i)^User-Agent$}]] < 0) ? \
               "BigIP/${tmm_vers} (HSSRv2.1)" : [lindex $headers [incr x]]}]
  append kopf "User-Agent: ${v}\r\n"

  if {[llength $headers] > 1} {
   foreach {n v} $headers {
    if {($n ne "!") &&
        ([lsearch -sorted $static::HSSR_done [string tolower $n]] < 0)} {
     append kopf "${n}:\x20${v}\r\n"
    }
   }
  }
 }

 #$crumbs format {name1 {dom1 path1 pathlen1 val1 exp1 secure1} name2 ...}
 if {[llength $cookies]} {
  set cdom [expr {$milk ? "***" : \
                  [expr {([string first "." $host] > 0) ? \
                         "*.${host}" : $host}] }]
  set cpth "/"
  set cpsz 1
  set cexp 2147485546 ; #we yield one second to propitiate Saturn
  set cscr 0

  foreach {n v} $cookies {
   set repl 0
   #cookie names and paths ARE case-sensitive
   foreach x [lsearch -all -exact $crumbs $n] {
    set c [lindex $crumbs [incr x]]
    if {([lindex $c 0] eq $cdom) && ([lindex $c 1] eq $cpth)} {
     set crumbs [lreplace $crumbs $x $x [lreplace $c 3 5 $v $cexp $cscr]]
     set repl 1
    }
   }
   if {!$repl} {
    lappend crumbs $n [list $cdom $cpth $cpsz $v $cexp $cscr]
   }
  }
 }

 if {$ffcount} {
  #prepare to submit form
  set w3c [list "%20" "+" "%0a" "%0d%0a"]
  set utf8 0
  set payload ""
  set sep ""
  foreach {n v} $form {
   append payload $sep [string map $w3c [URI::encode $n]]
   append payload "=" [string map $w3c [URI::encode $v]]
   incr utf8 [expr {![string is ascii "${n}${v}"]}]
   set sep "&"
  }

  if {($method eq "GET") || ($method eq "HEAD")} {
   append path [expr {([string first "?" $path] < 0) ? "?" : "&"}]
   append path $payload
  } else {
   set body $payload
   set bodylen [string bytelength $body]

   set type "application/x-www-form-urlencoded"
   #we only assert charset= if payload contains non-ASCII so server
   #will (generally) assume an acceptable charset, since we don't
   #really know what server wants and ASCII is broadly compatible
   if {$utf8} { append type "; charset=UTF-8" }
  }
 }

 if {$wait < 0.2} { set wait 0.2 } ; #some eager-beager will try "-wait 0"
 set wait_ms [expr {$wait * 1000}]

 if {$maxtime} {
  set maxclock [expr {[clock seconds] + $maxtime - ($timeout + $wait)}]
 }

 #max redirects we will follow
 set rtry 7

 set rslt 555
 set hlist [list]
 set booty "" ; set bootylen 0
 set mimetype "unk/unk"
 set charset "unk"
 set who [set where [set how [set what [set when ""]]]]
 while {[incr rtry -1] >= 0} {
  #to whom will we connect?
  if {$dest eq ""} {
   if {$ipv6} {
    set raddr $haddr
   } elseif {![catch {IP::addr $host mask 255.255.255.255}]} {
    set raddr [eval format "::ffff:%02x%02x:%02x%02x" [split $host "."]]
   } else {
    if {!( ([set tmp [lindex [eval "RESOLV::lookup ${nsvr} inet -a ${host}"] 0]] ne "") &&
           ([set raddr [eval format "::ffff:%02x%02x:%02x%02x" [split $tmp "."]]] ne "")
        ) &&
        ([set raddr [lindex [eval "RESOLV::lookup ${nsvr} inet6 -aaaa ${host}"] 0]] eq "") &&
        ($virt eq "")} {
     set e "cannot resolve ${host} to IP address"
     set rtry -2
     break
    }
   }
   set xhelper ""
   if {$virt eq ""} {
    set dest "${raddr}.${port}"
   } else {
    set dest $virt
    if {$raddr ne ""} {
     set xhelper "X-HSSR-Helper: [list $schm $raddr $port [virtual] $key]\r\n"
    }
   }
  }

  #canonicalize path
  regsub -all {(?://)|(?:[^/]+/[.][.]/)} $path "/" path

  #retry POST/whatever after redirect(s)?
  if {($what ne "") && ($who eq $server) && ($path eq $where)} {
   set method $how
   set body $what
   set what ""
   set expect $when
   set when ""
  }

  #cons up HTTP request
  set req [expr {($proxy eq "") ?
                 "${method} ${path} HTTP/1.1\r\n" :
                 "${method} ${schm}://${server}${path} HTTP/1.1\r\n"
                }]
  append req $xhelper
  append req $auth_hdrs

  if {$hostname eq ""} { set hostname $server }
  append req "Host: ${hostname}\r\n"

  if {($method ne "GET") && ($method ne "HEAD")} {
   #we handle Content-Length because caller might confuse chars and bytes
   append req "Content-Length: ${bodylen}\r\n"

   if {$bodylen} {
    if {$type ne ""} { append req "Content-Type: ${type}\r\n" }

    set dyt [clock format [clock seconds] -format "%a, %d %b %Y %T GMT" -gmt 1]
    append req "Date: ${dyt}\r\n"

    if {$expect} { append req "Expect: 100-Continue\r\n" }
   }
  }

  if {$nocache} { append req "Cache-Control: no-cache\r\nPragma: no-cache\r\n" }

  #purge expired cookies
  set tmp [list]
  set now [clock seconds]
  foreach {n c} $crumbs {
   if {[lindex $c 4] > $now} { lappend tmp $n $c }
  }
  set crumbs $tmp

  #assemble Cookie header
  if {[llength $crumbs]} {
   set tmp ""
   set plen [string length $path]
   foreach {n c} $crumbs {
    set cdom [lindex $c 0]
    set cpth [lindex $c 1]
    if {($rTLS || ![lindex $c 5]) && (
         ($ipv6 && ([string index $cdom 0] eq "\x5b") &&
          [IP::addr [string range $cdom 1 end-1] equals $haddr]) ||
         [string match $cdom $host] ||
         ( ([string index $cdom 0] eq "*") &&
           ([string range $cdom 2 end] eq $host)
         )
        ) && (
         ($path starts_with $cpth) &&
         ( ($plen == [set cpsz [lindex $c 2]]) ||
           ([string index $path $cpsz] eq "/") ||
           ([string index $cpth end] eq "/")
         )
        )} {
     append tmp "\x20${n}=[lindex $c 3];"
    }
   }
   #possibly jar holds no cookies for this host
   if {$tmp ne ""} { append req "Cookie:${tmp}\r\n" }
  }

  #bring in previously-prepared standard and custom headers
  append req $kopf

  append req "\r\n" ; #headers complete

  #Are we already or still connected?
  if {$connected &&
      ( ($cdest ne $dest) ||
        [catch {connect info -status $conn} sts] ||
        ([lsearch -sorted $static::HSSR_nogo [lindex [lindex $sts 0] 0]] > -1)
      )} {
   catch {close $conn}
   set connected false
  }
  #otherwise a little race...

  if {!$connected} {
   if {$debug} {
    log local0.info "${tkm} attempt connect to ${dest} '${server}' ${timeout} msec timeout"
   }
   if {[catch {connect -timeout $timeout -idle $idle -status sts $dest} conn] ||
       ($conn eq "")} {
    set e "connect to ${dest} '${server}' fails: ${sts} (${conn})"
    set rtry -2
    break
   }
   set connected true
   set cdest $dest
  }

  if {$debug} {
   log local0.info "${tkm} send to ${dest} '${server}' ${bodylen}-octet body, headers=${req}"
  }

  #we accept only one 100-Continue per POST/PUT attempt
  set pending 0
  set bites 2 ; #at the apple, lover
  while {[incr bites -1] >= 0} {
   if {$expect} {
    if {!$pending} {
     #I see you shiver with antici...
     set pending $bodylen ; set bodylen 0
    } else {
     #...pation
     set bodylen $pending ; set pending 0
    }
   }

   if {$req ne ""} {
    if {$debug} {
     log local0.info "${tkm} connected to ${dest} '${server}' sending [string length $req]-octet req headers"
     if {$pending} {
      log local0.info "${tkm} expecting 100-Continue before sending body"
     }
    }
    if {[catch {send -timeout $wait_ms -status sts $conn $req} sent] ||
        ($sts ne "sent") || ($sent != [string length $req])} {
     set e "send [string length $req]-octet req to ${dest} '${server}' fails: sent ${sent}, got status ${sts} (${sent})"
     break
    }
   }
   if {$bodylen} {
    if {$debug} {
     log local0.info "${tkm} sending ${bodylen}-octet body to ${dest} '${server}'"
    }
    if {[catch {send -timeout $wait_ms -status sts $conn $body} sent] ||
        ($sts ne "sent") || ($sent != $bodylen)} {
     set e "send $bodylen-octet body to ${dest} '${server}' fails: sent ${sent}, got status ${sts} (${sent})"
     break
    }
   }

   #default recv-poll interval is 50ms with max wait 10 secs
   #We adjust interval to -wait option
   set ctr 200
   set intvl [expr {int($wait_ms / $ctr)}] ; #keep this with initial ctr value
   set hdrs [set booty ""]
   set sts "unk"
   while {($ctr > 0) && ($sts ne "failed") && ($sts ne "closed")} {
    if {[catch {recv -peek -timeout $intvl -status sts $conn} reply]} {
     set e "peek hdrs fails: ${sts} (${reply})"
     break
    }

    if {[set hbrk [string first "\r\n\r\n" $reply]] > 0} {
     #TODO: support rfc5987 header-value charsets (priority: quite low)
     if {[catch {recv -status sts [incr hbrk 4] $conn} hdrs]} {
      set e "recv hdrs fails: ${sts} (${hdrs})"
      set hdrs ""
      break
     }
     if {$debug} {
      log local0.info "${tkm} reply hdrs [string map [list "\r\n" ",\x20"] $hdrs]"
     }

     #extract HTTP status code to $rslt
     if {([string length $hdrs] < 16) ||
         ![regexp {^HTTP/1[.][01]\x20([0-9]+)[^\r]*\r\n} $hdrs skip rslt]} {
      set e "server data unrecognized (not HTTP?), initial bytes:\x20"
      append e [URI::encode [string range $hdrs 0 31]]
      set hdrs ""
      break
     }
     set hdrs [string range $hdrs [string length $skip] end]

     if {($method eq "HEAD") || ($rslt == 204) || ($rslt starts_with "1")} {
      break
     }

     if {[regexp {(?i)Transfer-Encoding:[\x20\t]*Chunked} $hdrs]} {
      set bootylen 0
      set trail false
      while {$ctr > 0} {
       if {[catch {recv -peek -timeout $intvl -status sts $conn} chunk]} {
        set e "peek chunksz fails: ${sts} (${chunk})"
        break
       }

       if {$trail} {
        #flush optional trailing headers
        if {[string length $chunk] > 1} {
         if {( ($chunk starts_with "\r\n") && [set flush 2] ) ||
             ( ([set flush [string first "\r\n\r\n" $chunk]] >= 0) &&
               [incr flush 4] )} {
          if {[catch {recv -status sts $flush $conn} junk]} {
           set e "skip trailing headers fails: ${sts} (${junk})"
          }
          set trail false
          break
         }
        }
        incr ctr -1
        continue
       }

       set hex ""
       if {[regexp {^(?:[\r\n])*([0-9A-Fa-f]+)[^\r]*\r\n} $chunk skip hex] &&
           ($hex ne "0")} {
        if {[catch {recv -status sts [string length $skip] $conn} junk]} {
         set e "skip chunksz fails: ${sts} (${junk})"
         break
        }
        scan $hex "%x" chunksz
        if {$chunksz > 0} {
         if {($bootylen + $chunksz) > $maxbody} {
          set e "chunked body length exceeds -maxbody ${maxbody}"
          break
         }
         set z [expr {$ctr * $intvl}]
         if {![catch {recv -timeout $z -status sts $chunksz $conn} chunk] &&
             ([string length $chunk] == $chunksz)} {
          set booty [binary format a*a* $booty $chunk]
          incr bootylen $chunksz
         } else {
          set e "recv 0x${hex}=${chunksz}-octet chunk fails: ${sts} (${chunk})"
          break
         }
        }
       } elseif {$hex eq "0"} {
        if {[catch {recv -status sts [string length $skip] $conn} junk]} {
         set e "skip final chunksz fails: ${sts} (${junk})"
         break
        }
        set trail true ; #ignore optional trailing headers
        continue
       }
       incr ctr -1
      } ; #chunks loop
      if {$e eq ""} {
       if {$hex ne "0"} {
        set e "timed-out awaiting additional (or terminating zero-size) chunk"
       } elseif {$trail} {
        set e "timed-out while flushing optional trailing headers"
       }
      }
     } elseif {(![set clh [regexp {(?i)Content-Length:[\x20\t]*([0-9]+)} $hdrs junk clen]] &&
                [set clen $maxbody]) ||
               (($clen > 0) && ($clen <= $maxbody))} {
      set z [expr {$ctr * $intvl}]
      if {[catch {recv -timeout $z -status sts $clen $conn} booty] ||
          ([set bootylen [string length $booty]] < 0)} {
       set e "recv ${clen}-octet body fails: ${sts} (${booty})"
      } elseif {$clh && ($bootylen < $clen)} {
       set e "recv body fails (${sts}), got only ${bootylen} of Content-Length: ${clen} octets"
      }
     } elseif {$clen > $maxbody} {
      set e "Content-Length: ${clen} exceeds -maxbody ${maxbody}"
     }
     if {$e ne ""} {
      set booty "" ; set bootylen 0
     }
     #here we have reply headers, plus body if any, so stop polling
     break
    }

    incr ctr -1
   } ; #receive-poll (ctr) loop
   if {$e ne ""} {
    set rslt 555
    catch {close $conn}
    set connected false
    break
   }

   if {($hdrs eq "") && $expect && $pending && ($sts eq "timeout")} {
    if {$debug} {
     log local0.info "${tkm} wait for 100-Continue timed out--per rfc2616 send data now"
    }
    set req ""
    continue
   }

   if {$debug} {
    if {$ctr < 1} {
     log local0.info "${tkm} timed out awaiting response from ${dest} '${server}'"
    }
    log local0.info "${tkm} status ${rslt}, got [string length $hdrs] headers octets and ${bootylen} content octets"
   }
   if {$rslt != 100} {
    set bites -1
   } elseif {!$expect} {
    #rfc2616 allows unexpected 100-Continue
    set req ""
    set bodylen 0
    if {$debug} {
     log local0.info "${tkm} got unexpected 100-Continue from ${server}"
    }
   }

   if {$maxtime && ([clock seconds] > $maxclock)} {
    if {$debug} {
     log local0.info "${tkm} hit maxtime ${maxtime} secs after [expr {7 - $rtry}] redirects"
    }
    set rtry -1
    break
   }

   #compute default cookie path
   regexp {^/[^?#]*} $path ckypath
   if {[set x [string last "/" $ckypath]] > 0} { incr x -1 }
   set ckypath [string range $ckypath 0 $x]

   #remove LWS from headers
   set hdrs [regsub -all {[\x20\t]*\r\n[\x20\t]+} $hdrs "\x20"]

   #parse headers
   set mimetype "unk/unk"
   set charset "unk"
   set hlist [list]

   set hdrs [string map [list "\r\n" "\n"] $hdrs]
   set rlist [split $hdrs "\n"]
   foreach rline $rlist {
    if {![regexp {^([^:]+):[ \t]+(.*)} $rline junk n v]} { continue }
    set v [string trim $v]

    #I wish (September 2013) iRules had "switch -nocase"
    switch -- [string tolower $n] {
     "set-cookie" {
      set cky [set val [set opts ""]]
      #unlike some browsers we reject nameless cookies
      while {([string bytelength $v] < 4480) &&
             [regexp $static::HSSR_ckymatch $v junk cky val opts]} {
       if {[regexp {(?i)Domain=[.]?([^.;\x20\t][^;\x20\t]*)} $opts junk cdom]} {
        set cdom [string tolower $cdom]
        if {[string index $cdom 0] eq "\x5b"} {
         if {!$ipv6 || ![regexp $static::HSSR_ipv6match $cdom junk caddr] ||
             ![IP::addr $caddr equals $haddr]} {
          if {!$milk} { break }
          set cdom "***"
         }
        } elseif {[string first "." $cdom] < 1} {
         if {$cdom ne $host} {
          if {!$milk} { break }
          set cdom "***"
         }
        } elseif {![string match [set cdom "*.${cdom}"] $host]} {
         if {!$milk} { break }
         set cdom "***"
        }
       } else {
        set cdom [expr {$milk ? "***" : $host}]
       }

       #rfc6265 has ?query in cookie-path but not MS-IE and not us
       if {![regexp {(?i)Path=(/[^?#;]*)} $opts junk cpth]} {
        set cpth $ckypath
       }
       regsub -all {(?://)|(?:[^/]+/[.][.]/)} $cpth "/" cpth
       set cpsz [string length $cpth]

       set cexp 2147485546
       if {[regexp {(?i)Max-Age=([0-9]+)} $opts junk expdt]} {
        set cexp [expr {$expdt + [clock seconds]}]
       } elseif {[regexp {(?i)Expires=([^;]+);?} $opts junk expdt] &&
                 ![catch {clock scan $expdt -gmt 1} expdt]} {
        set cexp $expdt
       }

       set cscr [regexp {(?i)\ySecure;?\y} $opts]

       #cookie names and paths ARE case-sensitive
       set repl 0
       foreach x [lsearch -all -exact $crumbs $cky] {
        set c [lindex $crumbs [incr x]]
        if {([lindex $c 0] eq $cdom) && ([lindex $c 1] eq $cpth)} {
         set crumbs [lreplace $crumbs $x $x [lreplace $c 3 5 $val $cexp $cscr]]
         set repl 1
        }
       }
       if {!$repl} {
        lappend crumbs $cky [list $cdom $cpth $cpsz $val $cexp $cscr]
       }
       #expired cookies will be purged before next request
       break
      }
     }
     "location" {
      if {$redir && ($rslt > 300) && (($rslt < 304) || ($rslt == 307))} {
       if {($rslt <= 302) && ($redir == 1) && ($what eq "") &&
           (($method ne "GET") && ($method ne "HEAD"))} {
        set who $server
        set where $path
        set how $method
        set what $body
        set when $expect
       }
       if {$rslt <= 303} {
        set method "GET"
        set body ""
        set expect 0
       }
       if {$v starts_with "/"} {
        #relative path so contact same host
        if {![regexp {^/[^\x23]*} $v a] || ([string length $a] > 2040)} {
         set e "bogus redirect from ${dest} '${server}'"
         set rtry -2
         break
        }
        set s $schm
        set r $rTLS
        set h $host
        set p $port
       } elseif {[regexp $static::HSSR_urlsplit $v junk s toss lose h p a] &&
                 ([string length $a] < 2041) && ($a ne "*")} {
        set s [string tolower $s]
        set r [expr {[string index $s end] eq "s"}]
        set h [string tolower $h]
        if {[string index $h 0] eq "\x5b"} {
         set h [string map [list "%25" "%"] $h]
        } elseif {[string index $h end] eq "."} {
         set h [string range $h 0 end-1]
        }
        if {$p eq ""} { set p [expr {$r ? "443" : "80"}] }
        if {$a eq ""} { set a "/" }
       } else {
        #oops, Location not HTTP URI or path bogus
        set e "cannot follow redir from ${dest} '${server}' to ${v}"
        set rtry -2
        break
       }
      }
      #don't molest host/port/etc before swallowing all cookies
     }
     "connection" {
      if {$connected && ($rslt != 100) && [regexp {(?i)\yclose\y} $v]} {
       catch {close $conn}
       set connected false
      }
     }
     "content-length" {
      if {($v != $bootylen) && ($method ne "HEAD")} {
       #rfc2616 sec4.4 commands us to log
       log local0.err "${tkm} ${bootylen}-octet chunked body != Content-Length: ${v} from ${dest} '${server}'"
      }
     }
     "content-type" {
      set v [string tolower $v]
      regexp {^[^/;\x20\t]+/[^;\x20\t]+} $v mimetype
      if {![regexp {(?i)charset=([^;\x20\t]+)} $v junk charset] &&
          (($mimetype starts_with "text/") ||
           ($mimetype eq "application/javascript") ||
           ($mimetype eq "application/ecmascript")) && ($sniff != 2)} {
       set charset [expr {($sniff == 0) ? "iso-8859-1" : "utf-8"}]
      }
     }
     "www-authenticate" {
      if {($rslt == 401) && ($creds ne "") && [regexp {(?i)Basic\x20} $v]} {
       #We already sent "Authorization: Basic XXX" header but some servers
       #(f5 APM) will 401 first request and only look for creds on second
       #request (and change cookies too)
       set rslt 455
      }
     }
     "proxy-authenticate" {
      if {($rslt == 407) && ($pxy_uid ne "") && [regexp {(?i)Basic\x20} $v]} {
       set rslt 455 ; #what, again?
      }
     }
     "retry-after" {
      if {[regexp {^(503|(30[1237]))$} $rslt] && (
           ([regexp {^[0-9]+} $v delay] && $delay) ||
           ( ![catch {clock scan $v -gmt 1} dttm] &&
             ([set delay [expr {$dttm - [clock seconds]}]] > -1) )
          ) && (
           [set delay [expr {int(min($delay,($rtry * $wait / 2)))}]] &&
           ( !$maxtime ||
             (($delay + [clock seconds] + $timeout + $wait) < $maxclock) )
          )} {
       if {$debug} {
        log local0.info "${tkm} Retry-After, sleep ${delay} seconds"
       }
       after $delay ; #sleep
       if {$rslt == 503} { set rslt 455 }
       #otherwise follow redirect
      }
     }
    } ; #header name switch

    lappend hlist $n $v
   } ; #header parsing loop
  } ; #100-continue loop
  if {$e ne ""} {
   set rtry -2
   break
  }

  if {$rslt == 455} {
   #retry Basic authz, or after server-requested delay
   continue
  }

  #do we follow a redirect, or are we finished?
  if {!$redir || ($rslt < 301) || (($rslt > 303) && ($rslt != 307))} { break }

  #yay, redir!
  set path $a
  if {($schm ne $s) || ($host ne $h) || ($port ne $p)} {
   set schm $s
   set rTLS $r
   set host $h
   if {[set ipv6 [expr {[string index $host 0] eq "\x5b"}]]} {
    regexp $static::HSSR_ipv6match $host junk haddr
   }
   set port $p
   set server "${host}:${port}"
   set hostname ""

   if {$proxy ne ""} {
    #one benefit of proxy is single persistent connection
    continue
   }
   if {$virt eq ""} {
    set dest ""
   }
  }
 } ; #rtry loop
 if {$rtry == -1} {
  set e "too many redirects for -uri ${uri}"
 }
 if {($e eq "") && (($rslt == 401) || ($rslt == 407))} {
  set e "missing/unsupported credentials for (WWW|Proxy)-Authenticate demand"
 }

 if {$state ne ""} {
  set stvar [list $connected $conn $dest \
                  $virt $proxy $nsvr $crumbs $creds $kopf]
 } elseif {$connected} {
  catch {close $conn}
  set connected false
 }

 #NOTE:  as of August 2013 f5 has not corrected an awkwardness affecting
 #all data obtained from SIDEBAND recv, which involves string content
 #conversions between Latin-1 and UTF-8.  The code in this proc *assumes*
 #the presence of that glitch and will work around it, but when f5 does
 #fix the issue we may have to revisit this code.
 if {($rbody ne "") || ($rformat ne "") || ($rheaders ne "")} {
  if {$sniff > 2} {
   incr sniff -3
   set charset [lindex [list "iso-8859-1" "utf-8" "binary"] $sniff]
  }
  while {$charset eq "unk"} {
   if {$mimetype eq "application/json"} {
    set charset "utf-8"
    break
   }

   set charset "binary" ; #fallback, plus ensures loop-exit

   set take "a[expr {$bootylen & 0x3ff}]"
   set odor [binary format $take $booty]
   binary scan $odor c* miasma ; #scan *before* regexp or someone mangles

   if {$odor starts_with "\xef\xbb\xbf"} {
    set charset "utf-8"
    break
   }
   if {($odor starts_with "\xfe\xff") || ($odor starts_with "\xff\xfe")} {
    set charset "utf-16" ; #we neglect UTF-32
    break
   }

   if {[regexp $static::HSSR_quiver $odor contag] &&
       [regexp {(?i)[\x20\t]content=['\x22]?([^'\x22>]+)} $contag junk contype]} {
    set contype [string tolower $contype]
    regexp {^[^/;\x20\t]+/[^;\x20\t]+} $contype mymtype
    if {$mimetype eq "unk/unk"} { set mimetype $mymtype }

    if {![regexp {charset=([^;\x20\t]+)} $contype junk charset] &&
        (($mimetype starts_with "text/") ||
         ($mimetype eq "application/javascript") ||
         ($mimetype eq "application/ecmascript")) && ($sniff != 2)} {
     set charset [expr {($sniff == 0) ? "iso-8859-1" : "utf-8"}]
    }
    if {$charset ne "binary"} { break }
   }

   if {[regexp {/((xml)|([^;\x20\t]+[+]xml))} $mimetype]} {
    set charset "utf-8" ; #text/xml dfl is ASCII; UTF-8 common, incls. both
    #but next we check for overrides...
   }
   if {[regexp $static::HSSR_csetmeta $odor junk charset] ||
       [regexp $static::HSSR_xmlenc $odor junk charset]} {
    set charset [string tolower $charset]
   }
   if {$charset ne "binary"} { break }

   set may_ascii true
   set may_utf8 true
   set may_latin true
   set p 0
   foreach c $miasma {
    set c [expr {$c & 0xff}]
    if {$c > 0x7f} {
     set may_ascii false
     if {($c < 0xc0) && (($p < 0xc2) || ($p > 0xf4))} {
      set may_utf8 false
      if {!$may_latin} { break }
     }
     if {($c == 0x81) || ($c == 0x8d) ||
         ($c == 0x8f) || ($c == 0x90) || ($c == 0x9d)} {
      set may_latin false
      if {!$may_utf8} { break }
     }
    }
    set p $c
   }
   #no time/space here to sniff for, say, Big5
   if {$mimetype starts_with "text/"} {
    if {$may_utf8} {
     set charset "utf-8"
    } else {
     if {$may_latin} { set charset "iso-8859-1" }
    }
   } elseif {$may_ascii} {
    set charset "utf-8"
   }
  }
  if {($charset eq "windows-1252") ||
      ([string first "ascii" $charset] >= 0)} {
   set charset "iso-8859-1"
  }

  if {$rformat ne ""} {
   upvar 1 $rformat rtn_fmt

   set rtn_fmt [expr {(($charset eq "utf-8") || ($charset eq "iso-8859-1")) ?
                      "text" : "binary"}]
  }
  if {$rbody ne ""} {
   upvar 1 $rbody rtn_body

   if {$charset eq "utf-8"} {
    set rtn_body [URI::decode [URI::encode $booty]] ; #don't a-ask me why!
   } elseif {$charset eq "iso-8859-1"} {
    #What is it?
    #Evil, pure and simple, from the Eighth Dimension!
    set rtn_body ""
    append rtn_body $booty
    ###regexp {.*} $booty rtn_body
   } else {
    set rtn_body [binary format a* $booty]
   }
  }
 }
 if {$rheaders ne ""} {
  upvar 1 $rheaders rtn_headers

  lappend hlist "X-HSSR-Charset" $charset
  set rtn_headers $hlist
 }
 if {$rcookies ne ""} {
  upvar 1 $rcookies rtn_cookies

  set cookies [list]
  set now [clock seconds]
  foreach {n c} $crumbs {
   if {[lindex $c 4] > $now} {
    lappend cookies $n [lindex $c 3]
   }
  }
  set rtn_cookies $cookies
 }

 if {$e ne ""} {
  log local0.err "${tkm} ${e}"
 }
 return $rslt
 #At this point, http_req return value is HTTP status and
 #you may inspect your -(rbody|rheaders|rcookies|rformat)
 #variables for the results of your request
} ; #http_req


# After final [call /Common/HSSR::http_req -state xyz ...]
# SIDEBAND connection to remote server may remain open.
# Close it thusly:  [call /Common/HSSR::http_close xyz]
# (For lagniappe we also support [call /Common/HSSR::http_close $xyz])
#
proc http_close {stvar} {
 if {[catch {llength $stvar} varlen] || ($varlen == 1)} {
  upvar 1 $stvar state
 } else {
  set state $stvar
 }

 if {[catch {llength $state} stlen] || ($stlen < 9)} {
  set e "http_close argument must be xyz (or \x24xyz) from: http_req -state xyz"
  log local0.err $e
  return -code error $e
 }
 if {[lindex $state 0]} {
  catch {close [lindex $state 1]}
 }
 set state [list false {} "" "" "" "" [list] "" ""]
 return
} ; #http_close

#== End of Mark's HTTP Super SIDEBAND Requestor! (v2.1) ==============
