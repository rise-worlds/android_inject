# android_inject

## 准备frida服务端环境
1. 根据自己的平台下载frida服务端并解压
https://github.com/frida/frida/releases

2. 执行以下命令将服务端推到手机的/data/local/tmp目录
`adb push frida-server /data/local/tmp/frida-server`

3. 执行以下命令修改frida-server文件权限
`adb shell chmod 777 /data/local/tmp/frida-server`

4. 安装Python的运行环境
`pip install frida-tools`

## 准备客户端环境
1. 将一个脚本注入到Android目标进程
`frida -U -l myhook.js com.xxx.xxxx`
参数解释：
   * -U 指定对USB设备操作
   * -l 指定加载一个Javascript脚本
   * 最后指定一个进程名，如果想指定进程pid,用-p选项。正在运行的进程可以用frida-ps -U命令查看

2. 重启一个Android进程并注入脚本
`frida -U -l myhook.js -f com.xxx.xxxx`
参数解释：
   * -f 指定一个进程，重启它并注入脚本

> frida运行过程中，执行`%resume`重新注入，执行`%reload`来重新加载脚本；执行`exit`结束脚本注入
>

