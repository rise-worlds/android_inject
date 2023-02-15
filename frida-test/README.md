
```java
class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        while (true){
            try {
                Thread.sleep(1000)
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            sum(50, 30)
        }
    }
    private fun sum(x: Int, y: Int) {
        Log.d("sum", (x + y).toString())
    }
}
```
This snippet is a part of the android code, `onCreate` will be called when the app runs, it waits for 1 second and then calls function `sum` , and repeats forever.

Function `sum` will print the sum of the two arguments (80), logs can be viewed using logcat.

Now, we will use frida to change this result and these are the steps that we will follow:

1. start frida server
2. install the APK
3. run the APK and attach frida to the app.
4. hook the calls to function `sum` 
5. modify the arguments as we wish

##### Step 1:

Getting a root shell on the android emulator and executing frida-server.

*Note: Make sure that adb is in your PATH variable.*

```powershell
PS C:\Users\frida> adb shell
root@generic_x86:/ # /data/local/tmp/frida-server &
```

##### Step 2:

Installing the APK on the device

```powershell
PS C:\Users\frida> adb install .\Desktop\app-1.apk
.\Desktop\app-1.apk: 1 file pushed. 49.0 MB/s (1573086 bytes in 0.031s)
        pkg: /data/local/tmp/app-1.apk
Success
```

##### Step 3:

Frida injects Javascript into processes so we will write Javascript code, and it has python bindings so will write python to automate frida.

```python
#python code
import frida
import time

def my_message_handler(message , payload): #definition error handling
    print(message)
    print(payload)

device = frida.get_usb_device()
pid = device.spawn(["com.example.timetest"])
device.resume(pid)
time.sleep(1) #Without it Java.perform silently fails
session = device.attach(pid)
with open("s1.js", 'r', encoding='UTF-8') as f:
    script = session.create_script(f.read())
script.on("message" , my_message_handler) #register our handler to be called
script.load()
#prevent the python script from terminating
raw_input()
```

This piece of code will get the usb device (which is an android emulator in my case), starts the process, attaches to it and resumes that process.

You can get the package name from the APK as follows:

```bash
frida@frida:~/Desktop$ apktool d app-1.apk 
frida@frida:~/Desktop$ grep "package" ./app-1/AndroidManifest.xml 
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.timetest" platformBuildVersionCode="25" platformBuildVersionName="7.1.1">
```

#### Step 4&5:

Now we want to write some JS code that will be injected into the running process to extract/modify the arguments of the function call.

We already know the name of the function `sum` and the class that contains it `MainActivity`.

```javascript
console.log("Script loaded successfully ");
Java.perform(function x() { //Silently fails without the sleep from the python code
    console.log("Inside java perform function");
    //get a wrapper for our class
    var my_class = Java.use("com.example.timetest.MainActivity");
    //replace the original implmenetation of the function `fun` with our custom function
    my_class.sum.implementation = function(x,y){
    //print the original arguments
    console.log( "original call: sum("+ x + ", " + y + ")");
    //call the original implementation of `sum` with args (2,5)
    var ret_value = this.sum(2, 5);
    return ret_value;
    }});
```


## The result:

The function is now called with our arguments(2, 5)!
