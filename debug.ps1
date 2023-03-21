adb shell "su -c 'killall -9 inject_service'"
adb shell "rm /data/local/tmp/inject_service; rm /data/local/tmp/libinject_speed.so;"
adb push build/inject_service build/libinject_speed.so /data/local/tmp
adb shell "chmod 777 /data/local/tmp/inject_service"
adb forward tcp:9090 tcp:9090
adb forward tcp:10086 tcp:10086
adb shell "su -c '/data/local/tmp/lldb-server platform --listen *:9090 --server &' &"