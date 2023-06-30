[TOC]



# 本地搭建Doip_Server

## 项目基本信息

项目地址：http://www.automotive-doip.com/

项目结构：

```bash
.
├── EMS.properties # 定义EMS ecu基本信息，包含ecu name、ecu physical address等
├── EMS.uds #自定义诊断回复
├── TCU.properties
├── TCU.uds
├── doip-simulation.log
├── gateway.properties
├── libs
│   ├── doip-custom-simulation-1.1.5.jar
│   ├── doip-library-1.1.5.jar
│   ├── doip-logging-1.1.7.jar
│   ├── doip-simulation-1.4.1.jar
│   ├── log4j-api-2.11.2.jar
│   └── log4j-core-2.11.2.jar
├── log4j2.xml
├── standard.uds
└── start.sh
```



## 项目运行

在项目目录中直接运行`./start.sh gateway.properties` 即可启动服务



## 测试连接

```python
from pwn import *
# from LibcSearcher import *
context.log_level='debug'
debug = 0
file_name = './'
libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
ip = '127.0.0.1'
prot = '13400'
if debug:
    r = process(file_name)
    libc = ELF(libc_name)
else:
    r = remote(ip,int(prot))
    libc = ELF(libc_name)

def debug():
    gdb.attach(r)
    raw_input()


# file = ELF(file_name)
sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()
#Routing Activation
msg = "\x02\xFD\x00\x05\x00\x00\x00\x0b\xCC\xCC\x00\x00\x00\x00\x00\x00\x00\x00\x00"
sd(msg)
r.recv()
msg_2 = "\x02\xFD\x80\x01\x00\x00\x00\x06\xCC\xCC\x10\x01\x10\x01"
sd(msg_2)
r.recv()
ri()
```

激活路由

![image-20230629164319785](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20230629164319785.png)



进行诊断

![image-20230629164729215](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20230629164729215.png)



交互消息：

![image-20230629164745424](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20230629164745424.png)



## 遇到的问题

1、直接诊断日志中会出现`source address error`的错误，是因为没有激活路由，没有给tester注册逻辑地址。解决办法就是发送消息:`"\x02\xFD\x00\x05\x00\x00\x00\x0b\xCC\xCC\x00\x00\x00\x00\x00\x00\x00\x00\x00"`

