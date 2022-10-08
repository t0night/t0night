## 0x01 环境搭建

Ubuntu16.04、ICSim、wireshark、CAN Utils

安装参考：https://cloud.tencent.com/developer/article/1662635

运行`setup_vcan.sh`

```
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

加载can相关模块，创建can虚拟网卡

执行ifconfig查看网卡信息，可以看到vcan0网卡已经创建成功。

![img_v2_e6c028ea-3408-473a-b32f-b035e8c6b0dg](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/img_v2_e6c028ea-3408-473a-b32f-b035e8c6b0dg.jpg)

运行ICSim icsim和controls两个组件，icsim负责显示效果，controls负责发送发送指定can信号

![img_v2_2b7d7c44-b878-4282-88bc-cd0fbbdb61ag](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/img_v2_2b7d7c44-b878-4282-88bc-cd0fbbdb61ag.jpg)

| 行为           | 快捷键                   |
| :------------- | :----------------------- |
| 加速           | ↑                        |
| 左右转向       | ←/→                      |
| 解锁前左右车门 | Right-Shift + A/B        |
| 解锁后左右车门 | Right-Shift + X/Y        |
| 锁定全部车门   | Right-Shift + Left-Shift |
| 解锁全部车门   | Left-Shift + Right-Shift |









https://cloud.tencent.com/developer/article/1662635

https://bacde.me/post/hacking-all-the-cars-can-bus-reverse/

https://github.com/zombieCraig/ICSim

## 0x02 报文类型

数据帧、远程帧、错误帧、过载帧和帧间隔



















































## 0x00 帧类型

CAN-TP帧分为单帧和多帧

- 单帧（SF）：数据长度小于等于7时可用单帧传输（can fd为小于等于63）
- 多帧
  - 首帧（FF）
  - 流控帧（FC）
  - 连续帧（CF）





### SF

```bash
+-------------------------------------------+
|0 0 0 0 0 0 1 1|10 |02 |55 |55 |55 |55 |55 |
+-------------------------------------------+
|<--0-->|<-len->|<--------data------------->|
```

前四个bit固定为0，4-8字节表示有效字节数据长度为2，后续为填充的字节。



### FF 

```bash
+-------------------------------------------------------+
|0 0 0 1 0 0 0 0|0 0 0 1 0 1 0 0|2E |F1 |90 |01 |02 |03 |
+-------------------------------------------------------+
|<--1-->|<---------len--------->|<--------data--------->|
```

前四个bit固定为1, 4-16bit表示有效字节数据长度为20，后续为数据部分。



### FC

```bash
+-------------------------------------------------------------------+
|0 0 1 1 0 0 0 0|0 0 0 0 0 0 0 0|0 0 0 1 0 1 0 0|AA |AA |AA |AA |AA |
+-------------------------------------------------------------------+
|<--3-->|<--FS->|<-----len----->|<---STmin----->|<-----padding----->|
```

前四个bit固定为3。

4-8bit表示流状态，共有3中状态，分别是0（继续发送）、1（等待）、2（溢出）；该帧是接受数据者发给发送数据者的，为了是让发送方知道接收方当前的状态。

8-16bit表示允许一次连续发送的CF数量。当设置BlockSize为0时，告知发送端在其发送分段消息期间，接收端不会发送后续的FC；发送端网络应一次性把所有后续帧发送出去，而不用停下来等待接收端网络实体发送的FC。当设置BlockSize为0x01-0xff时，告知发送端，其在没有接收到接收端的流控帧期间；最多能发送的连续帧数量。

16-24bit（STmin）表示STmin（SeparationTime）参数用于表示发送相邻的连续帧所允许的最小时间间隔（一个连续帧发送完开始，到请求下一个连续帧时的间隔时长）



### CF

```bash
+-------------------------------------------+
|0 0 0 2 0 0 0 0|61 |62 |63 |64 |65 |66 |67 |
+-------------------------------------------+
|<--2-->|<--SN->|<--------data------------->|
```

前四个bit固定为2

4-8个bit为SN，值为0x00-0x0F，**首帧开始1-F，第二次循环0-F**。

其余为data



### 例子

1. Sender ->发送首帧

  2. Receiver ->回复流控帧

  3. Sender-> 发送连续帧（根据流控帧确认发送连续帧的间隔和次数）

  4. Receiver -> 收到指定数量的连续帧后，再次回复流控帧

  5.  Sender-> 发送连续帧（根据流控帧确认发送连续帧的间隔和次数）

![image-20220922162745559](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220922162745559.png)



https://blog.csdn.net/weixin_44536482/article/details/98652882

https://blog.csdn.net/weixin_47890316/article/details/121665919



https://blog.csdn.net/wteruiycbqqvwt/article/details/107671740  标准帧和扩展帧





![image-20220928154215925](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20220928154215925.png)



https://github.com/CaringCaribou/caringcaribou

https://github.com/zombieCraig/uds-server

