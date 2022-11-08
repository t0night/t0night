# 使用树莓派抓取CAN流量

准备材料：

- 树莓派PI3B

- 2-ChannelMC2518FD

将两个材料拼接到一起

![image-20221108165955819](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20221108165955819.png)



在”/boot/config.txt“文件末尾加一行：

```bash
dtoverlay=mcp251xfd,spi0-0,oscillator=20000000,interrupt=25
```



重启树莓派，设置波特率并且启动can0网卡

```bash
sudo ip link set can0 up type can bitrate 250000
```

## Referer

https://forum.opencyphal.org/t/how-to-use-the-raspberrypi-with-mcp2518fd-to-debug-uavcan/1091