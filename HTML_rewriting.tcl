#########################################################################
# title: HTML_rewriting.tcl                                             #
# author: Dario Garrido                                                 #
# date: 20210317                                                        #
# description: iRule for rewriting HTML content                         #
# references: https://support.f5.com/csp/article/K99872325              #
# configuration:                                                        #
# 1. Create /Profiles/Content/HTML/                                     #
# 2. Generate some HTML Rules                                           #
# >> A. Create "Raise Event on Tag"                                     #
# >>>> Match Tag Name: a                                                #
# >>>> Match Attribute Name: href                                       #
# >>>> Match Attribute Value: <empty>                                   #
# >> B. Create "Raise Event on Tag"                                     #
# >>>> Match Tag Name: link                                             #
# >>>> Match Attribute Name: href                                       #
# >>>> Match Attribute Value: <empty>                                   #
# >> C. Create "Raise Event on Tag"                                     #
# >>>> Match Tag Name: form                                             #
# >>>> Match Attribute Name: action                                     #
# >>>> Match Attribute Value: <empty>                                   #
# >> D. Create "Raise Event on Tag"                                     #
# >>>> Match Tag Name: script                                           #
# >>>> Match Attribute Name: src                                        #
# >>>> Match Attribute Value: <empty>                                   #
# 3. Assign this profile to your VS                                     #
# 4. Generate next iRule and assign it to the VS                        #
#########################################################################

when HTML_TAG_MATCHED {
	switch [HTML::tag name] {
		"form" {
			if { [HTML::tag attribute "action"] starts_with "/app/app/" }{
				HTML::tag attribute replace "action" [string map {"/app/app/" "/app/"} [HTML::tag attribute "action"]]
			}
		}
		"a" - "link" {
			if { [HTML::tag attribute "href"] starts_with "/app/app/" }{
				HTML::tag attribute replace "href" [string map {"/app/app/" "/app/"} [HTML::tag attribute "href"]]
			}
		}
		"script" {
			if { [HTML::tag attribute "src"] starts_with "/app/app/" }{
				HTML::tag attribute replace "src" [string map {"/app/app/" "/app/"} [HTML::tag attribute "src"]]
			}
		}
	}
}
