#########################################################################
# title: Get_iFile.tcl                                                  #
# author: Dario Garrido                                                 #
# date: 20200502                                                        #
# description: iRule for testing iFile usage                            #
#########################################################################

when HTTP_REQUEST {
    set var "HelloWorld!"
    #set response [subst -novar -nocommands -nobackslashes [ifile get iFile_Example]]
    #set response [subst -novar [ifile get iFile_Example]]
    #set response [subst -nocommands [ifile get iFile_Example]]
    #set response [subst -nobackslashes [ifile get iFile_Example]]
    set response [subst [ifile get iFile_Example]]
    HTTP::respond 200 -version 1.1 content $response noserver "Content-Type" "text/html; charset=utf-8" "Connection" "close"
}

##############################################
############### iFILE Example ################
##############################################
#<html>
#	<head>
#		<title>iRule iFile Example</title>
#	</head>
#	<body>
#		<h1>iRule iFile Example</h1>
#		<table border='1'>
#			<tr>
#				<td>Commands</td>
#				<td>Substitution</td>
#			</tr>
#			<tr>
#				<td>Variables</td>
#				<td>${var}</td>
#			</tr>
#			<tr>
#				<td>Square Brackets</td>
#				<td>[IP::client_addr]</td>
#			</tr>
#			<tr>
#				<td>Backslashes</td>
#				<td>\x48\x65\x6c\x6c\x6f\x57\x6f\x72\x6c\x64\x21</td>
#			</tr>
#		</table>
#	</body>
#</html>
