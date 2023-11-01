<?php
//本文件记录请求包内的所有数据
//引入方式如下两种，任选其一：
//1.在所需页面中加入【require_once("writeTolLog.php");】 
//2.修改php.ini设置auto_prepend_file = "【writeTolLog.php完整路径】";

logRequest();

function get_http_raw() { 
	$raw = ''; 
	$raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n"; 
	foreach($_SERVER as $key => $value) { 
		if(substr($key, 0, 5) === 'HTTP_') { 
			$key = substr($key, 5); 
			$key = str_replace('_', '-', $key); 
			 
			$raw .= $key.': '.$value."\r\n"; 
		} 
	}
	$raw .= "\r\n"; 
	$raw .= file_get_contents('php://input');
	return $raw; 
}

function logRequest(){
	$file  = 'log.txt';
	file_put_contents($file, get_http_raw(),FILE_APPEND);
}
?>