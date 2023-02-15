import time
import frida


def my_message_handler(message , payload): #定义错误处理
    print(message)
    print(payload)

# 连接安卓机上的frida-server
device = frida.get_usb_device()
# 启动`timetest`这个app
pid = device.spawn(["com.example.timetest"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)

# # 加载s1.js脚本
# with open("s1.js", 'r', encoding='UTF-8') as f:
#     script = session.create_script(f.read())
# script.on("message" , my_message_handler) #调用错误处理
# script.load()

# 加载s2.js脚本
with open("s2.js", 'r', encoding='UTF-8') as f:
    script = session.create_script(f.read())
script.on("message" , my_message_handler) #调用错误处理
script.load()

# 脚本会持续运行等待输入
input()