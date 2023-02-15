
Java.perform(function () {
    console.log("Script loaded successfully ");

    // Interceptor.attach(Module.getExportByName('libc.so', 'gettimeofday'), {
    //     onEnter: function (args) {
    //         // console.log('Context information:');
    //         // console.log('Context  : ' + JSON.stringify(this.context));
    //         // console.log('Return   : ' + this.returnAddress);
    //         // console.log('ThreadId : ' + this.threadId);
    //         // console.log('Depth    : ' + this.depth);
    //         // console.log('Errornr  : ' + this.err);

    //         var ts = args[0];
    //         var tz = args[1];
    //         if (!ts.isNull()) {
    //             var sec = ts.readU32();
    //             var temp = ts.add(4).readU32();
    //             var nsec = (sec * 1000000 + temp);
    //             if (sec != 0) {
    //                 console.log("gettimeofday: ", ts, tz);
    //                 console.log("ts: ", sec, nsec);
    //             }
    //         }
    //     },
    //     // onLeave: function(retval) {
    //     //     console.log(retval)
    //     //     // simply replace the value to be returned with 0
    //     //     retval.replace(0);
    //     // }
    // });

    // var base_sec = 0;
    // var gettimeofday_method = new NativeFunction(Module.findExportByName('libc.so', 'gettimeofday'), 'int', ['pointer', 'pointer']);
    // Interceptor.replace(Module.getExportByName('libc.so', 'gettimeofday'), new NativeCallback(function (ts, tz) {
    //     var result = gettimeofday_method(ts, tz);
    //     if (!ts.isNull()) {
    //         var sec = ts.readU32();
    //         var temp = ts.add(4).readU32();
    //         var nsec = (sec * 1000000 + temp);
    //         if (sec != 0) {
    //             if (base_sec == 0) {
    //                 base_sec = sec;
    //             }
    //             var new_sec = base_sec + (sec - base_sec) * 5;
    //             ts.writeU32(new_sec);
    //             // ts.add(4).writeU32(temp);
    //             console.log("gettimeofday: ", ts, tz);
    //             console.log("ts: ", sec);
    //             console.log("base ts: ", base_sec);
    //             sec = ts.readU32();
    //             nsec = (sec * 1000000 + temp);
    //             console.log("new ts: ", sec);
    //         }
    //     }
    //     return result;
    // }, 'int', ['pointer', 'pointer'])
    // );

    var gModifyTime = false;
    var outbufferptr = 0;
    var base_sec = 0, now_sec = 0;
    Interceptor.attach(Module.findExportByName("libtimetest.so", "Java_com_example_timetest_MainActivity_stringFromJNI"), {
        onEnter: function() {
            gModifyTime = true;
        }
    });
    Interceptor.attach(Module.findExportByName("libc.so", "gettimeofday"), {
        onEnter: function (args) {
            if (gModifyTime) {
                outbufferptr = args[0];
            }
        },
        onLeave: function (retval) {
            if (gModifyTime && !outbufferptr.isNull()) {
                now_sec = outbufferptr.readU32();
                if (base_sec == 0) {
                    base_sec = now_sec;
                }
                // console.log("---- base ---- ");
                // console.log(hexdump(outbufferptr, { length: 8, ansi: true }));
                // Memory.writeByteArray(outbufferptr, [0x91, 0x50, 0xc4, 0x5f, 0x15, 0x97, 0x09, 0x00]);
                Memory.writeU32(outbufferptr, base_sec + (now_sec - base_sec) * 5)
                // console.log("---- modify ---- ");
                // console.log(hexdump(outbufferptr, { length: 8, ansi: true }));
                gModifyTime = false;
                outbufferptr = null;
            }
        }
    });

    // Interceptor.attach(Module.getExportByName('libc.so', 'clock_gettime'), {
    //     onEnter: function(args) {
    //         // console.log('Context information:');
    //         // console.log('Context  : ' + JSON.stringify(this.context));
    //         // console.log('Return   : ' + this.returnAddress);
    //         // console.log('ThreadId : ' + this.threadId);
    //         // console.log('Depth    : ' + this.depth);
    //         // console.log('Errornr  : ' + this.err);
    //
    //         var clock = args[0].toInt32()
    //         var ts = args[1]
    //         if (!ts.isNull()) {
    //             var sec = ts.readU32();
    //             var temp = ts.add(4).readU32();
    //             var usec = Math.round(Math.floor((sec * 1000000 + temp) / 1000 + 0.5));
    //             if (sec != 0) {
    //                 console.log("clock_gettime: ", clock, ts);
    //                 console.log("ts: ", sec, usec);
    //             }
    //         }
    //     },
    //     // onLeave: function(retval) {
    //     //     console.log("onLeave:", retval.toInt32())
    //     //     // simply replace the value to be returned with 0
    //     //     retval.replace(0);
    //     // }
    // });
});
