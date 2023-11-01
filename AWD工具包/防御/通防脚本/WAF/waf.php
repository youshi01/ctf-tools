<?php
/**
 * PHP waf for AWD
 * User: moxiaoxi
 * Date: 2018/09/10
 * Time: 下午18:53
 */
namespace m0xiaoxi{
    //config start
    /*
     * WAF_MODE 1: just logger
     * WAF_MODE 2: logger and waf
     * WAF_MODE 3: loger and proxy
     * WAF_MODE 4: do nothing,just for test include
     * DEBUG 1: will echo debug info
     * FLAG_MODE 0: do nothing about flag
     * FLAG_MODE 1: change flag
     * FLAG_MODE 2: replace flag to ''
     * $white_ip_list $black_ip_list, can not run together! 
     * only one mode can be set up.
     */
    define('m0xiaoxi\WAF_MODE',2);
    define('m0xiaoxi\DEBUG',0);
    define('m0xiaoxi\LOGPATH',"/tmp/awd/");
    define('m0xiaoxi\FLAG_FORMAT', "/[0-9A-F\-]{32}/i");
    define('m0xiaoxi\FLAG_MODE',1);
    define('m0xiaoxi\PROXY_HOST','202.101.51.111');
    define('m0xiaoxi\PROXY_PORT',8008);
    define('m0xiaoxi\REWRITE_UPLOAD',true);
    $white_ip_list = array(); 
    $black_ip_list = array('127.0.2.1');
    //config end


    if(DEBUG){
        error_reporting(E_ERROR | E_WARNING | E_PARSE);
        ini_set('display_errors', 'On');
    }

    ob_start();
    register_shutdown_function('\m0xiaoxi\shutdown_func');
    libxml_disable_entity_loader(true);

    if(!check_log_path(LOGPATH)){
        echo("log path error");
    }


    switch (WAF_MODE){
        case 1:
            logger();
            break;
        case 2:
            logger();
            waf();
            break;
        case 3:
            logger();
            proxy(PROXY_HOST,PROXY_PORT);
            break;
        default:
            debug_echo('no such mode!');
            break;
    }


    /**
     * logger
     */
    function logger(){
        $get = $_GET;
        $post = $_POST;
        $cookie = $_COOKIE;
        $header = get_all_headers();
        $files = $_FILES;
        $input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);
        //judge whether a data flow is malicious
        foreach ($input as $k => $v) {
            foreach ($v as $kk => $vv) {
                check_attack_keyword($vv);
            }
        }
    }


    /**
     * waf
     */
    function waf(){
        global $white_ip_list,$black_ip_list;
        $remote_ip = $_SERVER['REMOTE_ADDR'];
        //if the white_ip_list is set, then receiving the traffic from the ip in the white_ip_list only
        // and the priority of the white list is higher than black list
        if(count($white_ip_list)>0){
            if(in_array($remote_ip,$white_ip_list)){
                return true;
            }
        }
        if(count($black_ip_list)>0){
            if(in_array($remote_ip, $black_ip_list)){
                not_found();
            }
        }

        $headers = get_all_headers();
        $files = $_FILES;
        $ip = $_SERVER["REMOTE_ADDR"];
        $method = $_SERVER['REQUEST_METHOD'];
        $filepath = $_SERVER["SCRIPT_NAME"];
        $body = file_get_contents('php://input');
        //if REWRITE_UPLOAD is set, rewrite shell which uploaded by others
        if(REWRITE_UPLOAD){
            foreach ($_FILES as $key => $value) {
                $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
                file_put_contents($_FILES[$key]['tmp_name'], "virink");
            }
        }
        debug_echo('#### filter before  #####');
        debug_var_dump($_GET);
        debug_var_dump($_POST);
        debug_var_dump($headers);
        foreach ($_GET as $key => $value) {
            $_GET[$key] = filter_dangerous_words($value);
        }
        foreach ($_POST as $key => $value) {
            $_POST[$key] = filter_dangerous_words($value);
        }
        foreach ($headers as $key => $value) {
            $_SERVER[$key] = filter_dangerous_words($value);
        }
        debug_echo('#### filter after  #####');
        debug_var_dump($_GET);
        debug_var_dump($_POST);
        debug_var_dump($headers);
    }


    /**
     * not found
     */
    function not_found(){
        header('HTTP/1.1 404 Not Found');
        echo('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
            <html><head>
            <title>404 Not Found</title>
            </head><body>
            <h1>Not Found</h1>
            <p>The requested URL '.$_SERVER['REQUEST_URI'].' was not found on this server.</p>
            <hr>
            <address>'.$_SERVER['SERVER_SOFTWARE'].'/2.4.7 (Ubuntu) Server at '.$_SERVER['SERVER_ADDR'].' Port '.$_SERVER['SERVER_PORT'].'</address>
            </body></html>');
        die();
    }


    /**
     * 检查返回包
     */
    function check_response($str){
        if(preg_match(FLAG_FORMAT, $str,$data)){
            $flag ='';
            foreach ($data as $value){
                $flag.=$value;
            }
            write_attack_log("GETFLAG:".$flag);
            if(FLAG_MODE==1){
                foreach ($data as $value){
                    $result = preg_replace(FLAG_FORMAT,encrypt($value),$str);
                }
                ob_clean();
                die($result);
            }elseif (FLAG_MODE==2){
                $result = preg_replace(FLAG_FORMAT,'',$str);
                ob_clean();
                die($result);
            }

        }
    }

    /*
    * 判断字符串是否为XML格式
    * param $data
    * return True/False
    */
    function xml_parser($str){
        $xml_parser = xml_parser_create();
        if(!xml_parse($xml_parser,$str,true)){
            xml_parser_free($xml_parser);
            return false;
        }else {
            return (json_decode(json_encode(simplexml_load_string($str)),true));
        }
    }

    /*
     * 判断字符串是否为序列化字符串。
     * param $data
     * return True/False
     */
    function is_serialized( $data ) {
        $data = trim( $data );
        if ( 'N;' == $data )
            return true;
        if ( !preg_match( '/^([adObis]):/', $data, $badions ) )
            return false;
        switch ( $badions[1] ) {
            case 'a' :
            case 'O' :
            case 's' :
                if ( preg_match( "/^{$badions[1]}:[0-9]+:.*[;}]\$/s", $data ) )
                    return true;
                break;
            case 'b' :
            case 'i' :
            case 'd' :
                if ( preg_match( "/^{$badions[1]}:[0-9.E-]+;\$/", $data ) )
                    return true;
                break;
        }
        return false;
    }

    /*
     * 依据攻击关键字分类写入payload
     */
    function check_attack_keyword($str){
        # sqli
        if(preg_match("/select\b|load_file\b|insert\b|update\b|drop\b|delete\b|dumpfile\b|outfile\b|load_file|substr\(|binary\(|rename\b|floor\(|extractvalue|updatexml|ascii\(|name_const|multipoint\(/i", $str)){
            write_log('sqli');
        }

        # 文件包含
        if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
            $tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
            if(preg_match("/\.\.|.*\.php[2345]/i", $tmp)){
                write_log("LFI/LFR");;
            }
        }
        if(preg_match("/(php|ftp|phar|zip):\/\//i", $str)){
            write_log("LFI/LFR");
        }
        if(preg_match("/data:text\/plain;/i", $str)){
            write_log("LFI/LFR");
        }

        # 文件读取
        if(preg_match("/file_get_contents\(|fopen\(|readfile\(|fgets\(|fread\(|parse_ini_file\(|highlight_file\(|fgetss\(|show_source\(/i",$str)){
            write_attack_log("READFILE");
        }

        # 文件写入
        if(preg_match("/unlink\(|copy\(|fwrite\(|file_put_contents\(|bzopen\(/i", $str)){
            write_attack_log("WRITEFILE");
        }

        # 攻击测试
        if(preg_match("/phpinfo\(|echo\(|unlink(__FILE__)|\/etc\/passwd/i", $str)){
            write_attack_log("/phpinfo\(|echo\(|unlink(__FILE__)|\/etc\/passwd/i");
        }

        # 代码执行
        if(preg_match("/array_map\(|base64_decode\(|eval\(|call_user_func\(|system\(|assert\(/i", $str)){
            write_attack_log("CODE EXEC");
        }

        # 命令执行
        if(preg_match("/exec|system|chroot|scandir|passthru|exec|system|chroot|scandir
        |chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore|`|dl|openlog
        |syslog|readlink|symlink|popepassthru|stream_socket_server|escapeshellcmd|assert|pcntl_exec/i", $str)){
            write_attack_log("SYSTEM EXEC");
        }

        #XXE
        if(preg_match("/<!DOCTYPE|<!ENTITY|PUBLIC/i", $str)){
            write_attack_log("XXE");
        }
        if(xml_parser($str)){
            write_attack_log("XXE");
        }
        # 序列化
        if(is_serialized($str)){
            write_attack_log("serialized ATTACK");
        }

        # 后门
        if(preg_match("/haozi|curl|kill|bash|flag|str_rot13\(|str_rot\(|md5\(/i",$str)){
            write_attack_log("Webshell");
        }

    }


    /**
     * 得到所有HTTP头
     * @return array
     */
    function get_all_headers() {
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_')
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
        }
        return $headers;
    }

    /**
     * PHP结束函数
     */
    function shutdown_func(){
        write_log('clear');
        $str = ob_get_contents();
        check_response($str);
    }



    /*
    * 简单将易出现问题的字符替换成中文
    */
    function filter_dangerous_words($str){
        $str = str_replace("'", "‘", $str);
        $str = str_replace("\"", "“", $str);
        $str = str_replace("<", "《", $str);
        $str = str_replace(">", "》", $str);
        $str = str_replace("(","（", $str);
        $str = str_replace(")"," ）", $str);
        $str = str_replace(";"," ；", $str);
        $str = str_replace(","," ，", $str);
        return $str;
    }

    /*
     * 写入攻击日志
     * param $alert  log信息
     * return True
     */
    function write_attack_log($alert){
        $data = str_repeat("=",100)."\r\n";
        $data .= date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".get_http_raw()."\r\n\r\n";
        $data .= str_repeat("-",100)."\r\n";
        $data .= "Response:\r\n".ob_get_contents()."\r\n\r\n";
        write("all_payload",$data);
        $ip = $_SERVER['REMOTE_ADDR'];
        write('payload_'.$ip,$data);
        return True;
    }

    /*
     * 写入log
     * param $alert  log信息
     * return True
     */
    function write_log($alert){
        $data = str_repeat("=",100)."\r\n";
        $data .= date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".get_http_raw()."\r\n\r\n";
        $data .= str_repeat("-",90)."\r\n";
        $data .= "Response:\r\n".ob_get_contents()."\r\n\r\n";
        write("all",$data);
        $ip = $_SERVER['REMOTE_ADDR'];
        write($ip,$data);
        return True;
    }

    /**
     * @param $path
     * @return bool
     */
    function check_log_path($path){
        if (is_dir($path)){
            #echo 'okay';
        }else{
            $res=mkdir(iconv("UTF-8", "GBK", $path),0777,true);
            if ($res){
                echo "mkdir $path succ<br>";
            }else{
                echo "mkdir $path error<br>";
                return False;
            }
        }
        return True;
    }


    /**
     * @param $msg
     */
    function debug_echo($msg){
        if(DEBUG){
            echo $msg;
        }
    }

    /**
     * @param $msg
     */
    function debug_var_dump($msg){
        if(DEBUG){
            var_dump($msg);
        }
    }

    /*
     * 获取http的请求包，意义在于获取别人的攻击payload
     * param $path  路径
     * return True  如果失败，return False
     */
    function get_http_raw() {
        $raw = '';
        $raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
        foreach(get_all_headers() as $key => $value){
            $raw .=   $key.": ".$value."\n";
        }
        $is_first = true;
        $raw .= "\n";
        foreach($_POST as $key => $value){
            if(!$is_first){ $raw .= '&';}
            $raw .= $key."=".$value;
            $is_first = false;
        }
        return $raw;
    }


    /*
     * 写入操作
     * param $filename  要写入文件的名字
     * param $data      要写入的内容
     * return True
     */
    function write($filename,$data){
        $myfile = fopen(LOGPATH.$filename.'.log', "a");
        flock($myfile, LOCK_EX);
        fwrite($myfile, $data);
        fflush($myfile);
        flock($myfile, LOCK_UN);
        fclose($myfile);
    }

    /**
     * @param $str
     * @return mixed
     */
    function encrypt($str){
        for($i=0;$i<strlen($str);$i++){
            $ascii = ord($str[$i]);
            if(($ascii>=97)&&($ascii <='122')){
                $str[$i] = chr(97+($ascii+3)%97);
            }elseif(($ascii>=65)&&($ascii <='90')){
                $str[$i] = chr(97+($ascii+3)%97);
            }
        }
        return $str;
    }

    /**
     * 代理模式
     * @param $host
     * @param $port
     */
    function proxy($host, $port){
        /*
        this function is used forward the traffic to other server, just like a transparent proxy
        */

        //get basic info
        $method = $_SERVER['REQUEST_METHOD'];
        $url = 'http://' . $host .':'. $port . $_SERVER['REQUEST_URI'];
        $query = $_SERVER['QUERY_STRING'];
        $headers = getallheaders();
        $body = file_get_contents('php://input');
        foreach($_POST as $key=>$value){
            $data[$key] = $value;
        }
        foreach($_GET as $key=>$value){
            $data[$key] = $value;
        }
        foreach($_COOKIE as $key=>$value){
            $data[$key] = $value;
        }
        debug_echo('#### proxy request starts #####');
        debug_var_dump($headers);
        debug_var_dump($body);
        debug_echo('#### proxy request ends #####');

        //send request
        //change the header of host to the value of the real server
        $headers['Host'] = $host .':'. $port;
        // if there is extra output, the accept-encoding should not be gzip
        $headers['Accept-Encoding'] = 'awd_proxy';
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

        $new_headers = array();
        foreach ($headers as $key => $value) {
            array_push($new_headers, $key.': '.$value);
        }

        curl_setopt($curl, CURLOPT_HTTPHEADER, $new_headers);
        curl_setopt($curl, CURLOPT_HEADER,1);
        if($method=='GET'){
            ;
        }else if($method=='POST'){
            curl_setopt($curl,CURLOPT_POSTFIELDS,$body);
            curl_setopt($curl,CURLOPT_POST,1);
        }else{
            exit('unknown method: '.$method);
        }
        $res = curl_exec($curl);
        $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);

        // record the server response according to the config
        $tmp = substr($res,0,100);
        if(strlen($tmp)==100){
            $tmp = $tmp.'...';
        }

        write("proxy",$tmp);
        $response_headers = substr($res, 0, $headerSize);
        $response_body = substr($res, $headerSize);
        curl_close($curl);
        debug_echo('#### proxy reply starts #####');
        debug_var_dump($response_headers);
        debug_var_dump($response_body);
        debug_echo('#### proxy reply ends #####');
        check_response($response_body);
        //update the headers
        $tmp = array_slice(explode("\r\n",$response_headers),1);
        foreach($tmp as $line){
            if($line!==''&& !strstr($line,"Transfer-Encoding")){
                //list($key,$value) = explode(":",$line,2);
                header($line);
            }
        }
        //output the body
        echo $response_body;
        exit();

    }

}