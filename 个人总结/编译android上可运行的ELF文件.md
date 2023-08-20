在车机渗透时，遇到需要在安卓车机上运行自己写的工具，有两种解决办法

1、使用golang进行编译，参数：`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build target.go`



2、搭建NDK编译环境，编译ELF文件

下载位置：

https://developer.android.google.cn/ndk/downloads?hl=zh-cn

![image-20230820155710596](https://raw.githubusercontent.com/wxm-radish/uPic/main/uPic/image-20230820155710596.png)



在终端运行以下命令进行安装

```bash
 python3.8 ./make_standalone_toolchain.py --arch arm64 --api 24 --install-dir ~/android-build
```

安装好之后，编译测试文件：

```bash
~/android-build/bin/aarch64-linux-android-gcc -pie -fPIE test.c -o debug-test -ldl
```



将编译好的文件上传到车机的android系统上运行就不会出现格式错误的问题