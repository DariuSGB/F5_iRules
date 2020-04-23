############################################################################
# title: Table_Export.tcl                                                  #
# author: Joe Pruitt                                                       #
# date: 20200423                                                           #
# description: iRule for exporting subtables                               #
# usage: Access <scheme>://<virtual>/exporttable                           #
# https://devcentral.f5.com/s/articles/session-table-exporting-with-irules #
# https://devcentral.f5.com/s/articles/session-table-export                #
############################################################################

when HTTP_REQUEST {
    switch -glob [string tolower [HTTP::uri]] {
        "/exporttable" {
            HTTP::respond 200 content {
                <html><head><title>iRule Table Exporter</title></head>
                <script language="JavaScript">
                function SubmitForm() {
                    var submit = false;
                    var value = document.getElementById("table_name");
                    if ( null != value ) {
                        if ( "" != value.value ) {
                            document.export_table_form.action = "/exporttable/" + value.value;
                            submit = true;
                        } else {
                            window.alert("Please Enter a table name");
                            value.focus();
                        }
                    }
                    return submit;
                }
                </script>
                <body>
                    <h1>iRule Table Exporter</h1>
                    <form method="get" name="export_table_form" action="">
                        <table border='1'>
                            <tr>
                                <td>Table Name</td>
                                <td><input type="text" Id="table_name" value=""></td>
                                <td><input type="submit" value="Submit" onclick="javascript:return SubmitForm()"></td>
                            </tr>
                        </table>
                    </form>
                </body>
            }
        }
        "/exporttable/*" {
            set csv "Table,Key,Value\n";
            set tname [getfield [HTTP::uri] "/" 3]
            foreach key [table keys -subtable $tname] {
                append csv "${tname},${key},[table lookup -subtable $tname $key]\n";
            }
            set filename [clock format [clock seconds] -format "%Y%m%d_%H%M%S_${tname}.csv"]
            set disp "attachment; filename=${filename}";
            HTTP::respond 200 content $csv "Content-Type" "text/csv" "Content-Disposition" $disp;
            return;    
        }
    }
}
