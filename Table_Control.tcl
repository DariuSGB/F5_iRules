##########################################################################
# title: Table_Control.tcl                                               #
# author: Joe Pruitt                                                     #
# date: 20200423                                                         #
# description: iRule for managing subtables using browser                #
# usage: Access <scheme>://<virtual>/subtables                           #
# https://devcentral.f5.com/s/articles/session-table-control-with-irules #
# https://devcentral.f5.com/s/articles/session-table-control             #
##########################################################################

when HTTP_REQUEST {
	set APPNAME "subtables";
	# Set initial variables
	set luri  [string tolower [HTTP::uri]]
	set app   [getfield $luri "/" 2];
	set cmd   [getfield $luri "/" 3];
	set tname [URI::decode [getfield [HTTP::uri] "/" 4]];
	set arg1  [URI::decode [getfield [HTTP::uri] "/" 5]];
	set arg2  [URI::decode [getfield [HTTP::uri] "/" 6]];
	set send_response 1;
	set resp "";
	# Check if we are accessing the application
	if { $app equals $APPNAME } {
		#log local0. "Processing application $app...";
		if { $cmd eq "" } { set cmd "edit"; }
		if { $tname eq "file" } { set tname ""; }
		#log local0. "INCOMING URI: $luri, app=$app, cmd=$cmd, tname=$tname";
		set TABLENAME_FORM "
<form method='get' name='export_table_form' action=''>
	<table border='0' class='bottom'>
	<tr>
		<td>Table Name</td>
		<td><input type='text' Id='table_name' value=''></td>
		<td><input type='submit' value='Submit' onclick='javascript:return SubmitForm()'></td>
	</tr>
	</table>
</form>
<script Language='JavaScript'>
var tn = document.getElementById('table_name');
if ( null != tn ) { tn.focus(); }
</script>
";
		set FILEINPUT_FORM "
<form method='post' enctype='multipart/form-data' action='/$APPNAME/import/file'>
<table cellpadding='0' cellspacing='0' border='0' class='bottom'>
  <tr><td>File</td><td><input type='file' accept='text/csv' name='filedata'></td></tr>
  <tr><td></td><td align='right'><input type='submit' value='Import'></td></tr>
</table>
</form>
";
		append resp "
<html>
<head>
	<title>iRule Table Control</title>
	<meta charset='utf-8'>
	<style type='text/css'>
		body,td,th { font-family: Tahoma; font-size: 12px; }
		.top { background-color: #D0D0D0; }
		.bottom { background-color: C0C0C0; }
		.tkey { text-align: center; }
		.tvalue { font-family: Lucida Console; }
	</style>
</head>
<script language='JavaScript'>
function SubmitForm()
{
	var submit = false;
	var value = document.getElementById('table_name');
	if ( null != value ) {
		if ( '' != value.value ) {
			document.export_table_form.action = '/${APPNAME}/${cmd}/' + value.value;
			submit = true;
		} else {
			window.alert('Please Enter a table name');
			value.focus();
		}
	}
	return submit;
}
</script>
<body>
	<table border='1' cellpadding='0' cellspacing='0' width='100%' height='100%'>
	<tr><td align='center' valign='top' class='top'>
	<center><h1><a href='/${APPNAME}'>iRule Table Control</a>($cmd)</h1>
	<a href='/${APPNAME}/edit/${tname}'>edit</a> |
	<a href='/${APPNAME}/export/${tname}'>export</a> |
	<a href='/${APPNAME}/import/'>import</a> |
	<a href='/${APPNAME}/delete/${tname}'>delete</a><hr/><p>
";

		#------------------------------------------------------------------------
		# Process commands
		#------------------------------------------------------------------------
		switch $cmd {
			
			"edit" {
			#----------------------------------------------------------------------
			# edit
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: edit";
				if { $tname eq "" } {
					append resp $TABLENAME_FORM
				} else {
					append resp "
<script language='JavaScript'>
function SubmitInsert() {
	var submit = false;
	var tname = document.getElementById('table_name');
	var tkey = document.getElementById('table_key');
	var tvalue = document.getElementById('table_value');
	if ( (null != tname) && (null != tkey) && (null != tvalue) ) {
		if ( '' == tname.value ) {
			alert('Couldnt find hidden form value for tablename');
			return;
		}
		if ( '' == tkey.value ) {
			tkey.focus();
			return;
		}
		if ( '' == tvalue.value ) {
			tvalue.focus();
			return;
		}
		window.location.href = '/${APPNAME}/insertkey/' + tname.value  + '/' + 
		tkey.value + '/' + tvalue.value;
	}
	return submit;
}
</script>";
					append resp "<input type='hidden' id='table_name' value='${tname}'>\n";
					append resp "<table border='1' cellpadding='5' cellspacing='0'>\n";
					append resp "<tr><th colspan='3'>'$tname' Table</th></tr>\n";
					append resp "<tr><th>Key</th><th colspan='2'>Value</th></tr>\n";
					foreach key [table keys -subtable $tname] {
						append resp "<tr><td class='tkey'>$key</td>";
						append resp "<td class='tvalue'>[table lookup -subtable $tname $key]</td>";
						append resp "<td>\[<a href='/${APPNAME}/deletekey/${tname}/${key}'>X</a>\]</td>";
						append resp "</tr>\n";
					}
					# Add insertion fields
					append resp "<tr><td class='tkey'><input type='text' id='table_key' value=''></td>";
					append resp "<td class='tvalue'><input type='text' id='table_value' value=''></td>";
					append resp "<td>\[<a href='#' onClick='SubmitInsert();'>+</a>\]</td>";
					append resp "</table>\n";
					append resp "
<script Language='JavaScript'>
var tkey = document.getElementById('table_key');
if ( null != tkey ) { tkey.focus(); }
</script>";
				}
			}
			
			"export" {
			#----------------------------------------------------------------------
			# export
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: export";
				if { $tname eq "" } {
					append resp $TABLENAME_FORM
				} else {
					set csv "Table,Key,Value\n";
					foreach key [table keys -subtable $tname] {
						append csv "${tname},${key},[table lookup -subtable $tname $key]\n";
					}
					set filename [clock format [clock seconds] -format "%Y%m%d_%H%M%S_${tname}.csv"]
					#log local0. "Responding with filename $filename...";
					set disp "attachment; filename=${filename}";
					HTTP::respond 200 content $csv "Content-Type" "text/csv" "Content-Disposition" $disp;
					return;
				}
			}
			
			"import" {
			#----------------------------------------------------------------------
			# import
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: import";
				if { [HTTP::method] eq "GET" } {
					append resp $FILEINPUT_FORM;
				} else {
					append resp "SUBMITTED FILE...";
					if { [HTTP::header exists "Content-Length"] } {
						#log local0. "Collecting [HTTP::header Content-Length] bytes...";
						HTTP::collect [HTTP::header "Content-Length"];
						set send_response 0;
					} else {
						#log local0. "Content-Length header doesn't exist!";
					}
				}
			}
			
			"delete" {
			#----------------------------------------------------------------------
			# delete
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: delete";
				if { $tname eq "" } {
					append resp $TABLENAME_FORM
				} else {
					table delete -subtable $tname -all;
					append resp "<h3>Subtable $tname successfully deleted</h3>";
				}
			}
			
			"deletekey" {
			#----------------------------------------------------------------------
			# deletekey
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: deletekey";
				if { ($tname ne "") && ($arg1 ne "") } {
					#log local0. "Deleting subtable $tname key $arg1...";
					table delete -subtable $tname $arg1;
					HTTP::redirect "http://[HTTP::host]/${APPNAME}/edit/${tname}";
					return;
				}
			}
			
			"insertkey" {
			#----------------------------------------------------------------------
			# insertkey
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: insert";
				if { ($tname ne "") && ($arg1 ne "") && ($arg2 ne "") } {
					#log local0. "Inserting subtable $tname key $arg1...";
					table set -subtable $tname $arg1 $arg2 indefinite indefinite
					HTTP::redirect "http://[HTTP::host]/${APPNAME}/edit/${tname}";
					return;
				}
			}
		}
		if { $send_response == 1 } {
			append resp "</center></td></tr></table></body></html>";
			HTTP::respond 200 content $resp;
		}
	}
}

when HTTP_REQUEST_DATA {
	#log local0. "HTTP_REQUEST_DATA -> app $app";
	if { $app eq $APPNAME } {
		switch $cmd {
			"import" {
			#----------------------------------------------------------------------
			# import
			#----------------------------------------------------------------------
				#log local0. "SUBCOMMAND: import";
				set payload [HTTP::payload]
				#------------------------------------------------------------------------
				# Extract Boundary from "Content-Type" header
				#------------------------------------------------------------------------
				set ctype [HTTP::header "Content-Type"];
				set tokens [split $ctype ";"];
				set boundary "";
				foreach {token} $tokens {
					set t2 [split [string trim $token] "="];
					set name [lindex $t2 0];
					set val [lindex $t2 1];
					if { $name eq "boundary" } {
						set boundary $val;
					}
				}
				#------------------------------------------------------------------------
				# Process POST data
				#------------------------------------------------------------------------
				set in_boundary 0;
				set in_filedata 0;
				set past_headers 0;
				set process_data 0;
				set num_lines 0;
				if { "" ne $boundary } {
					#log local0. "Boundary '$boundary'";
					set lines [split [HTTP::payload] "\n"]
					foreach {line} $lines {
						set line [string trim $line];
						#log local0. "LINE: '$line'";
						if { $line contains $boundary } {
							if { $in_boundary == 0 } {
								#----------------------------------------------------------------
								# entering boundary
								#----------------------------------------------------------------
								#log local0. "Entering boundary";
								set in_boundary 1;
								set in_filedata 0;
								set past_headers 0;
								set process_data 0;
							} else {
								#----------------------------------------------------------------
								# exiting boundary
								#----------------------------------------------------------------
								#log local0. "Exiting boundary";
								set in_boundary 0;
								set in_filedata 0;
								set past_headers 0;
								set process_data 0;
							}
						} else {
							#------------------------------------------------------------------
							# in boundary so check for file content
							#------------------------------------------------------------------
							if { ($line starts_with "Content-Disposition: ") &&
							($line contains "filedata") } {
								#log local0. "In Filedata";
								set in_filedata 1;
								continue;
							} elseif { $line eq "" } {
								#log local0. "Exiting headers";
								set past_headers 1;
							}
						}
						if { $in_filedata && $process_data } {
							#log local0. "Appending line";
							if { ($num_lines > 0) && ($line ne "") } {
								#----------------------------------------------------------------
								# Need to parse line and insert into table
								# line is format : Name,Key,Value
								#----------------------------------------------------------------
								set t [getfield $line "," 1];
								set k [getfield $line "," 2];
								set v [getfield $line "," 3] 
								if { ($t ne "") && ($k ne "") && ($v ne "") } {
									#log local0. "Adding table '$t' entry '$k' => '$v'";
									table set -subtable $t $k $v indefinite indefinite
								}
							}
							incr num_lines;
						}
						if { $past_headers } {
							#log local0. "Begin processing data";
							set process_data 1;
						}
					}
				}
				incr num_lines -2;
				append resp "<h3>Successfully imported $num_lines table records</h3>";
				append resp "</center></td></tr></table></body></html>";
				HTTP::respond 200 content $resp;
			}
		}
	}
}
