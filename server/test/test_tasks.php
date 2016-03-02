<?php 
ini_set("memory_limit","256M"); 
error_reporting (E_ALL);

define ("CM_PORT", 8001);
define ("CM_SERVER_IP", "127.0.0.1");
define ("CLIENT_VERSION", "8.2.2");
define ("TEST_CASE_DIR", "task_test_case/");
define ("TEST_RESULT_DIR", "task_test_result/");
define ("TEST_CONFIG_DIR", "task_test_config/");

if($argc != 2){
    echo "usage: php test_tasks.php <output_file_path>\n";
    exit;
}
$cubrid_env = getenv('CUBRID');
$cubrid_database_env = getenv('CUBRID_DATABASES');
if(!$cubrid_env || !$cubrid_database_env){
    echo "cubrid related environment variable not set.\n";
    exit;
}

$outputfile = $argv[1];
$outfp = fopen($outputfile, "w");
if(!$outfp){
    echo "failed to create output file: ".$outputfile."\n";
    exit;
}

$task_seq = array(
    "cmd,cub_js",
    "cmd,cub_auto",    
    "cmd,cub_auto --version",        
    "login_nullid,failure",
    "login_notask,failure",
    "login_nouser,failure",
    "login_errpasswd,failure",
    "dbmtuserlogin,success",
    "updatedbmtuser_admin,success",
    "updatedbmtuser_nullid,failure",    
    "updatedbmtuser_errformat,failure",       
    "setdbmtpasswd_admin,success",
   
    "startinfo,success",

    "getdbmtuserinfo,success",
    "userverify,success",
    "userverify_fail,failure",
    "adddbmtuser,success",
    "adddbmtuser_existid,failure",
    "adddbmtuser_lilo,success",
    "adddbmtuser_nullid,failure",
    "adddbmtuser_nullpasswd,failure",            
    "setdbmtpasswd,success",
    "setdbmtpasswd_errid,failure", 
    "setdbmtpasswd_errpasswd,failure", 
    "setdbmtpasswd_nullid,failure", 
    "setdbmtpasswd_nullpasswd,failure", 
    "updatedbmtuser_newuser,success",

    "checkdir,success",

    "createdb,success",
    "createdb_fail_with_dup_name,failure",
    "createdb_accesslog,failure",
    "createdb_errlogpath,failure",
    "createdb_errlogpath1,failure",
    "createdb_errvolpath,failure",
    "createdb_nulldbname,failure",
    "createdb_nulllogsize,failure",
    "createdb_nullnumpage,failure",
    "createdb_nullpagesize,failure",
    "createdb_nullvolpath,failure",
       
    "startdb,success",
    "startdb_fail,failure",

    "checkdb,success",
    "checkdb_nullname,failure",    
    "getdbsize,success",
    "gettransactioninfo,success",
    //"killtransaction,success",

    // add vol, then spacedb
    "addvoldb,success",
    "addvoldb_bigsize,failure",
    "addvoldb_nullpurpose,failure",
    "addvoldb_nullsize,failure",
    "lockdb,success",
    "backupdb,success",
    "backupdb_nulldir,failure",
    "backupdb_nullname,failure",
    "backupdb_rep,failure",
    "backupdbinfo,success",

    // test auto tasks.
    "addbackupinfo,success",
    "getbackupinfo,success",
    "getbackuplist,success",
    "setbackupinfo,success",
    "setautoexecquery,success",
    //"cmd,sleep 1m",
    "getautoexecquery,success",
    "getautoexecqueryerrlog,success",
    "getautobackupdberrlog,success",
    "deletebackupinfo,success",

    "optimizedb,success",
    "stopdb,success",
    "backupvolinfo,success",
    "loaddb,success",
    "restoredb,success",
    "compactdb,success",
    "copydb,success",

    "addstatustemplate,success",
    "updatestatustemplate,success",
    "getstatustemplate,success",
    "removestatustemplate,success",

    "addtrigger,success",
    "altertrigger,success",
    //"gettriggerinfo,success",
    //"droptrigger,success",

    "getautoaddvol,success",
    "getautoaddvollog,success",
    "getaddvolstatus,success",
    "setautoaddvol,success",

    "getlogfileinfo,success",
    "getlogfileinfo_nobroker,success",
    "getlogfileinfo_errbroker,success", 
    "getlogfileinfo_logbroker,success",
    "getloginfo,success",
    "viewlog,success",
    "removelog,success",


    "startinfo,success",
    //"setsysparam,success",
    "setsysparam_errconf,failure",
    "setsysparam_nullconf,failure",    

    /* delete new database */
    "deletedbmtuser,success",
    "deletedbmtuser_erruser,failure",
    "deletedbmtuser_nullid,failure",
    "deletedbmtuser_lilo,success",
    "renamedb,success",
    "renamedb_nullrename,failure",
    "renamedb_adoff,failure",
    "renamedb_erropen,failure",        
    "unloaddb,success",
    "unloaddb_advance,success",
    "unloaddb_nullname,failure",
    "unloaddb_nulltarget,failure",
    "unloaddb_nulltargetdir,failure",                
    "deletedb,success",

    /* broker api related tasks */
    "stopbroker,success",
    "startbroker,success",
    "getaddbrokerinfo,success",
    "getbrokerdiagdata,success",
    "getbrokersinfo,success",
    "getbrokerstatus,success",
    "broker_stop,success",
    "broker_stop_errbroker,failure",
    "broker_stop_nullbroker,failure", 
    "broker_start,success",
    "broker_start_errbroker,failure",
    "broker_start_nullbroker,failure", 
    "broker_restart_errbroker,failure",
    "broker_restart_nullbroker,failure",            
    "broker_restart,success",
    "broker_setparam,success",
    //"deletebroker,success",
    "executecasrunner,success",
    /* db api related tasks */
    "class,success",
    "classinfo,success",
    "gettriggerinfo,success",
    "optimizedb,success",
    "updateattribute,success",
    "userinfo,success",
    "createuser,success",
    "updateuser,success",
    "updateuser_nullpasswd,failure",   
    "updateuser_nopasswd,failure",      
    "deleteuser,success",
    /* other tasks */
    "unloadinfo,success",
    "loadaccesslog,success",
    "deleteaccesslog,success",
    "deleteerrorlog,success",
    "checkfile,success",
    "analyzecaslog,success",
    "analyzecaslog_option_no,success",
    "getadminloginfo,success",
    "getallsysparam,success",
    "getallsysparam_errorconf,failure",
    "getallsysparam_nullconf,failure",    
    "getenv,success",
    "resetlog,success",

    "getcaslogtopresult,success",
    "removecasrunnertmpfile,success",
    "paramdump,success",
    "paramdump_nullname,failure",    
    "statdump,success",
    "statdump_nullname,failure",      
    "plandump,success",
    "plandump_nullname,failure",

    // create a new database to test copydb.
    "createdb_for_copydb,success",
    "copydb_advance,success",
    "copydb_nulldest,failure",
    "copydb_nulldestpath,failure",
    "copydb_nullexvolpath,failure",
    "copydb_nulllogpath,failure",
    "copydb_nullop,failure",
    "copydb_nullsrc,failure",
    "deletedb_for_copydb,success",

    // get host stat
    "gethoststat,success",
    "getdbprocstat,success",
    "getdbprocstat_all,success",
    "changemode,success",
    "getstandbyserverstat,success",
    //"rolechange,success",
    "getdbmode,success",
    "heartbeatlist,success",
    
    // tasks set conf files
    //"setsysparam_cmconf,success",
    //"setsysparam_cubridconf,success",
    //"broker_setparam,success",

    "createftprocess,success",
    "runsqlstatement,success",
    "removefiles,success",
    "jobtest,success",
);



$test_res = array();

$ntask_total = 0;
$ntask_failed = 0;
$ntask_success = 0;

/* connect cub_auto process to get valid token */

$sock_auto = socket_create (AF_INET, SOCK_STREAM, SOL_TCP);
if ($sock_auto < 0)
{
    echo "socket_create() failed: reason: ".socket_strerror ($sock_auto)."\n";
}

$token = get_token($sock_auto);
#echo "token = ".$token."\n";

/* connect cub_js process to execute tasks */
exec_tasks($token);

echo "tasks executed:\t\t".$ntask_total."\n";
echo "tasks success:\t\t".$ntask_success."\n";
echo "tasks failed:\t\t".$ntask_failed."\n";

print_test_suites($ntask_total, $ntask_failed, 0, $test_res);

#system("sleep 10");
socket_close ($sock_auto);

function get_time_next_miniute($pattern){
   date_default_timezone_set('PRC');
   $date = time();
   $date_time_array = getdate($date);
   $minutes = $date_time_array["minutes"];
   $minutes += 1;
   $hour= $date_time_array["hours"];

   $time = (date ($pattern, mktime($hour, $minutes)));
   return $time;
}


function exec_tasks($token)
{
    build_env();

    global $task_seq;
    foreach($task_seq as $task){
	$tmp_str = explode (",", $task);
	if (!strcmp ($tmp_str[0], "cmd")){
		echo "run cmd".$tmp_str[1]."\n";
		system($tmp_str[1]);
		continue;
	}
	if(!file_exists(TEST_CASE_DIR.$tmp_str[0])){
            echo "file ".TEST_CASE_DIR.$task." not exist.\n";
            exit;
        }
        exec_task($tmp_str[0], $token, $tmp_str[1]);
    }

    clean_env();
    
}

function build_env()
{
    global $cubrid_env, $cubrid_database_env;
    @system("rm -rf ".TEST_RESULT_DIR);  //remove old result dir
    system("mkdir ".TEST_RESULT_DIR);  //create an empty result dir
    system("mkdir ".$cubrid_database_env."/copylogdb");  //create an empty dir for copylogdb
    system("mkdir ".$cubrid_database_env."/applylogdb");  //create an empty dir for applylogdb
    system("mkdir ".$cubrid_database_env."/destinationdb1");  //create an empty dir for destinationdb1
    system("cp ".TEST_CONFIG_DIR."tmp_file_for_test/* ".$cubrid_env."/tmp/");  //create an empty dir for applylogdb
    system("echo task:class > ".$cubrid_env."/tmp/DBMT_comm_test.req");
    system("echo dbname:testclass >> ".$cubrid_env."/tmp/DBMT_comm_test.req");
}

function clean_env()
{
    global $cubrid_database_env;
    @system("rm -rf ".$cubrid_database_env."/copylogdb");  //remove copylogdb dir
    @system("rm -rf ".$cubrid_database_env."/applylogdb");  //remove applylogdb dir
    system("rm -rf ".$cubrid_database_env."/destinationdb1");  //remove an empty dir for destinationdb1
    system("rm -rf ".$cubrid_database_env."/destinationdb");  //remove an empty dir for destinationdb1
    system("rm -rf ".$cubrid_database_env."/copydb");  //remove an empty dir for destinationdb1
}

function exec_task($req_file, $token, $test_result)
{

    global $ntask_total;
    global $ntask_failed;
    global $ntask_success;
    global $test_res;

    $sock_js = socket_create (AF_INET, SOCK_STREAM, SOL_TCP);
    if ($sock_js < 0)
    {
        echo "socket_create() failed: reason: ".socket_strerror ($sock_js).
            "\n";
    }

    $result = socket_connect ($sock_js, CM_SERVER_IP, CM_PORT+1);
    if ($result < 0)
    {
        echo "socket_connect() failed.\nReason: ($result) ".
            socket_strerror ($result)."\n";
        exit;
    }

    $contents = file_get_contents(TEST_CASE_DIR . $req_file);
    $contents = replace_env_vars($contents);     /* replace cubrid relate env var to actual path */
    #$kv_arr = string_to_kv_arr($contents);
    #$kv_arr["token"] = $token;
    $contents = setval_with_key($contents,"token", $token);
    #echo $contents;
    echo "processing file: ". $req_file . "\t\t";

    #$req = build_request($kv_arr);
    $req = $contents."\n";
    $resp = '';
    #echo $req;
    socket_write ($sock_js, $req, strlen ($req));

    while ($resp .= socket_read ($sock_js, 2048))
    {
        if(substr($resp, -2) == "\n\n")
            break;
    }

    #echo $resp."\n";

    if(getval_with_key($resp, "status") != $test_result){
        echo "[\x1b[31m FAIL \x1b[0m]\n";
        $ntask_failed++;
	echo $resp."\n";
	$err_msg = getval_with_key ($resp, "note");
	$err_msg = str_replace ('<end>','.', $err_msg);
	$err_msg = str_replace ("\"", ' ', $err_msg);

        $test_res[] = array("name" => $req_file, "succ" => 0, "err_msg" => $err_msg);
    }else{
        echo "[\x1b[32m OK \x1b[0m]\n";
        $ntask_success++;
        $test_res[] = array("name" => $req_file, "succ" => 1, "err_msg" => "succ");
    }
    $ntask_total++;

    /*
    $handle = fopen(TEST_RESULT_DIR.$req_file.".res", "w");
    fwrite($handle, $resp);
    fclose($handle);
     */
    while(socket_read($sock_js, 1024))      /* read response message to maximize lcov */
        ;

    socket_close ($sock_js);
}

function get_token($sock_auto)
{
    $result = socket_connect ($sock_auto, CM_SERVER_IP, CM_PORT);
    if ($result < 0)
    {
        echo "socket_connect() failed.\nReason: ($result) ".
            socket_strerror ($result)."\n";
        exit;
    }

    $req = "id:admin\n";
    $req .= "password:admin\n";
    //$req .= "password:1111\n";
    $req .= "clientver:".CLIENT_VERSION."\n\n";
    $resp = '';

    socket_write ($sock_auto, $req, strlen ($req));

    while ($resp .= socket_read ($sock_auto, 2048))
    {
        if(substr($resp, -2) == "\n\n")
            break;
    }


    if(getval_with_key($resp, "status") != "success"){
        #echo "error: ".$kv_resp["note"];
        echo "error: ".getval_with_key($resp, "note");
        echo "\n";
        exit;
    }
    return getval_with_key($resp, "token");

}

function getval_with_key($string, $key_in, $line_delim="\n", $kv_delim=":")
{
    $arr = array();
    $tmp_arr = explode($line_delim, $string);
    foreach($tmp_arr as $elem){
        if(empty($elem))
            continue;
        @list($key, $val) = explode($kv_delim, $elem);
        if($key == $key_in)
            return $val;
    }
    return "";
}
function setval_with_key($string, $key_in, $val_in, $line_delim="\n", $kv_delim=":")
{
    $out_str = "";
    $arr = array();
    $tmp_arr = explode($line_delim, $string);
    foreach($tmp_arr as $elem){
        if(empty($elem))
            continue;
        @list($key, $val) = explode($kv_delim, $elem);
        if($key == $key_in){
            $out_str .= $key_in . $kv_delim . $val_in . $line_delim;
        }
        else{
            $out_str .= $elem.$line_delim;
        }
    }
    return $out_str;
}

function replace_env_vars($contents)     /* replace cubrid relate env var to actual path */
{
    global $cubrid_env, $cubrid_database_env;
    
    $tmp_time = get_time_next_miniute("Y-m-d:Hi");
    $time_elem = explode (":", $tmp_time);
    $contents = str_replace('$AUTO_DATE', $time_elem[0], $contents);
    $contents = str_replace('$AUTO_TIME', $time_elem[1], $contents);

    $query_time = get_time_next_miniute ("Y/m/d H:i");
    echo $query_time;
    $contents = str_replace('$AUTO_QUERY_TIME', $query_time, $contents);

    $contents = str_replace('$CUBRID_DATABASES', $cubrid_database_env, $contents);
    $contents = str_replace('$CUBRID', $cubrid_env, $contents);

    return $contents;
}

function print_test_suites($ntests, $ntests_failed, $time_elapsed, $result_arr)
{
    global $outfp;

    $classname = "CMSERVER_TEST";


    fwrite($outfp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    fwrite($outfp, "\n");

    fwrite($outfp, "<testsuites tests=\"{$ntests}\" failures=\"{$ntests_failed}\" disabled=\"0\" errors=\"0\" time=\"{$time_elapsed}\" name=\"AllTests\">");
    fwrite($outfp, "\n");

    fwrite($outfp, "<testsuite name=\"{$classname}\" tests=\"{$ntests}\" failures=\"{$ntests_failed}\" disabled=\"0\" errors=\"0\" time=\"{$time_elapsed}\">");
    fwrite($outfp, "\n");

    foreach($result_arr as $item){
        print_test_case($item["name"], "run", $time_elapsed, $classname, $item["succ"], $item["err_msg"]);
    }

    fwrite($outfp, "</testsuite>");
    fwrite($outfp, "\n");
    fwrite($outfp, "</testsuites>");
    fwrite($outfp, "\n");

}

function print_test_case($name, $status, $time, $classname, $succ, $err_msg)
{
    global $outfp;
    fwrite($outfp, "<testcase name=\"{$name}\" status=\"{$status}\" time=\"{$time}\" classname=\"{$classname}\">");
    fwrite($outfp, "\n");
    if(!$succ){
        fwrite($outfp, "<failure message=\"{$err_msg}\" type=\"\"></failure>");
        fwrite($outfp, "\n");
    }
    fwrite($outfp, "</testcase>");
    fwrite($outfp, "\n");
}

?>
