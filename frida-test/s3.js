// import "frida-il2cpp-bridge";

// Il2Cpp.perform(() => {
//     console.log(Il2Cpp.unityVersion);
    
//     Il2Cpp.trace()
//         .assemblies(Il2Cpp.Domain.assembly("Assembly-CSharp"))
//         .and()
//         .attach("full");
// });

Java.perform(function x() {
    console.log("Inside java perform function");
    
    var base_address = Module.findBaseAddress('libil2cpp.so');

    if (base_address) {
        console.log(':初始化成功, base:', base_address);

        var set_fixedDeltaTime_addr = base_address.add(0x7669EC);
        var get_fixedDeltaTime_addr = base_address.add(0x7669B8);
        var set_fixedDeltaTime = new NativeFunction(set_fixedDeltaTime_addr, 'void', ['float']);
        var get_fixedDeltaTime = new NativeFunction(get_fixedDeltaTime_addr, 'float', []);
        console.log('set_fixedDeltaTime, addr:', set_fixedDeltaTime_addr);
        console.log('get_fixedDeltaTime, addr:', get_fixedDeltaTime_addr);
        console.log('get_fixedDeltaTime', get_fixedDeltaTime());
        set_fixedDeltaTime(0.10);
        console.log('get_fixedDeltaTime', get_fixedDeltaTime());
        console.log();

        var set_timeScale_addr = base_address.add(0x766A64);
        var get_timeScale_addr = base_address.add(0x766A30);
        var set_timeScale = new NativeFunction(set_timeScale_addr, 'void', ['float']); 
        var get_timeScale = new NativeFunction(get_timeScale_addr, 'float', []); 
        Interceptor.attach(set_timeScale_addr, {
            onEnter: function(args) {
                console.log('set_timeScale onEnter');
            },
            onLeave: function(ret) {
                console.log('set_timeScale onLeave', ret);
            }
        });
        console.log('set_timeScale, addr:', set_timeScale_addr);
        console.log('get_timeScale, addr:', get_timeScale_addr);
        console.log('get_timeScale', get_timeScale());
        set_timeScale(5.0);
        console.log('get_timeScale', get_timeScale());
    }
});