#include <fcntl.h>
#include <pthread.h>
#include <frida-gum.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <memory>
#include <Logger.hpp>
#include <ResolverInit.hpp>
#include <httplib/httplib.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/android_sink.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

static std::string process_name;
static int pid;
static int server_port = 10086;
static int g_speed = 1.0;
static bool g_modify_time = false;
static struct timeval g_tv = {0, 0};
static struct timespec g_ts = {0, 0};
static std::shared_ptr<std::thread> gp_run;

constexpr const char *cocos2d_mornal[] = {
    "_ZN7cocos2d11CCScheduler6updateEf", // cocos2dx cpp 3.7.1
    "_ZN7cocos2d9Scheduler6updateEf",    // cocos creator 2.4.11
    "_ZN7cocos2d9SchedulerC2Ev",         // cocos2dx cpp old?
};

constexpr const char *cocos2d_special[] = {
    "_ZN7cocos2d15CCActionManager6updateEf",
    "_ZN7cocos2d11CCScheduler4tickEf",
    "_ZN7cocos2d13ActionManager6updateEf",      // cocos2dx cpp 3.7.1
    "_ZN7cocos2d5Speed4stepEf",                 // cocos2dx cpp 3.7.1
    "_ZN7cocos2d4Node8scheduleEMNS_3RefEFvfEf", // cocos2dx cpp 3.7.1
};

constexpr const char *cocoscreatro_special[] = {
    "Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender",          // cocos2dx cpp 3.7.1 / cocos creator 2.4.11
    "Java_com_google_androidgamesdk_GameActivity_loadNativeCode",   // cocos creator 3
    "GameActivity_onCreate",                                        // cocos creator 3
};

typedef void (*cocos2dx_update_fun)(void *v, float dt);
typedef void *(*cocos2dx_update_fun2)(void *v, float dt);
typedef bool (*cocos2dx_update_fun3)(void *v, float dt);
typedef void (*cocos_jni_GameActivity_loadNativeCode)(void *env, void* javaGameActivity, void* path, void* funcName, void* internalDataDir, void* obbDir, void* externalDataDir, void* jAssetMgr, void* savedState);
typedef void (*cocos_jni_GameActivity_onCreate)(void *v, void* savedState, size_t size);
static gpointer cocos_normal_update1 = nullptr;
static gpointer cocos_normal_update2 = nullptr;
static gpointer cocos_normal_update3 = nullptr;
static gpointer cocos_special_update1 = nullptr;
static gpointer cocos_special_update2 = nullptr;
static gpointer cocos_special_update3 = nullptr;
static gpointer cocos_special_update4 = nullptr;
static gpointer cocos_special_update5 = nullptr;
static gpointer cocos_jni_nativeRender = nullptr;
static gpointer cocos_jni_loadNativeCode = nullptr;
static gpointer cocos_jni_onCreate = nullptr;
static bool waitCocosSoLoaded = false;
static bool isCocosCreator = false;

cocos2dx_update_fun COCOS_NORMAL_UPDATE;
static void cocos_normal_update_hook(void *v, float dt);

cocos2dx_update_fun COCOS_SPECIAL_UPDATE_ONE;
static void cocos_special_update_hook_one(void *v, float dt);

cocos2dx_update_fun2 COCOS_SPECIAL_UPDATE_TWO;
static void *cocos_special_update_hook_two(void *v, float dt);

cocos2dx_update_fun2 COCOS_SPECIAL_UPDATE_THREE;
static void *cocos_special_update_hook_three(void *v, float dt);

cocos2dx_update_fun3 COCOS_SPECIAL_UPDATE_FOUR;
static bool cocos_special_update_hook_four(void *__hidden, float radio);

cocos2dx_update_fun2 COCOS_SPECIAL_UPDATE_FIVE;
static void *cocos_special_update_hook_five(void *envirenment, float delater);


// u3d
static unsigned long il2cppAddress = 0;  // 存储il2cpp.so基地址
int (*Screen$$get_height)();             // 预定义一个方法
int (*Screen$$get_width)();              // 预定义一个方法
float (*Time$$get_timeScale)();          // 预定义一个方法
void (*Time$$set_timeScale)(float);      // 预定义一个方法
float (*Time$$get_deltaTime)();          // 预定义一个方法
float (*Time$$get_fixedDeltaTime)();     // 预定义一个方法
void (*Time$$set_fixedDeltaTime)(float); // 预定义一个方法

// static int open_hook(const char *path, int oflag, ...);
static int pthread_create_hook(void*, void*, void*, void*);
static int gettimeofday_hook(struct timeval *tv, struct timezone *tz);
static int clock_gettime_hook(clockid_t clock, struct timespec *ts);

static gpointer pthread_create_origin_address = nullptr;
static gpointer gettimeofday_origin_address = nullptr;
static gpointer clock_gettime_origin_address = nullptr;

inline int64_t getUnixTimestamp()
{
    auto duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

static gboolean foundModule(const GumModuleDetails *details, gpointer user_data)
{
    const char *name = details->name;
    const char *path = details->path;
    SPDLOG_INFO("module name: {}", name);
    SPDLOG_INFO("base: {:#08x}, size: {}, {}", details->range->base_address, details->range->size, path);

    if (std::strcmp(name, "libil2cpp.so") == 0) {
        il2cppAddress = details->range->base_address;
        return false;
    }

    cocos_normal_update1 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_mornal[0]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update1));
    cocos_normal_update2 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_mornal[1]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update2));
    cocos_normal_update3 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_mornal[2]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update3));
    cocos_special_update1 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_special[0]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update1));
    cocos_special_update2 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_special[1]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update2));
    cocos_special_update3 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_special[2]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update3));
    cocos_special_update4 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_special[3]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update4));
    cocos_special_update5 = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocos2d_special[4]));
    // SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update5));

    cocos_jni_nativeRender = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocoscreatro_special[0]));
    cocos_jni_loadNativeCode = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocoscreatro_special[1]));
    cocos_jni_onCreate = reinterpret_cast<gpointer>(gum_module_find_export_by_name(name, cocoscreatro_special[2]));

    waitCocosSoLoaded = (cocos_normal_update1 != nullptr) || (cocos_normal_update2 != nullptr) || (cocos_normal_update3 != nullptr) || (cocos_special_update1 != nullptr) || (cocos_special_update2 != nullptr) || (cocos_special_update3 != nullptr) || (cocos_special_update4 != nullptr) || (cocos_special_update5 != nullptr) || (cocos_jni_nativeRender != nullptr) || (cocos_jni_loadNativeCode != nullptr) || (cocos_jni_onCreate != nullptr);
    return !waitCocosSoLoaded;
}

void initUnity3Dil2cpp()
{
    SPDLOG_INFO("get il2cpp address: {:#08x}", il2cppAddress);
// 初始化il2cpp API
#define DO_API(r, n, p) n = (r(*) p)gum_module_find_export_by_name("libil2cpp.so", #n)
#include "Il2cppApi/il2cppApiFunctions.h"
#undef DO_API
    // il2cpp_resolve_icall = reinterpret_cast<Il2CppMethodPointer (*)(const char *name)>(gum_module_find_export_by_name("libil2cpp.so", "il2cpp_resolve_icall"));
    SPDLOG_INFO("get il2cpp_resolve_icall address: {}", fmt::ptr(il2cpp_resolve_icall));

    do
    {
        // il2cpp_init
        InitResolveFunc(Screen$$get_height, "UnityEngine.Screen::get_height");
        SPDLOG_DEBUG("get UnityEngine.Screen::get_height address: {}", fmt::ptr(Screen$$get_height));
        InitResolveFunc(Screen$$get_width, "UnityEngine.Screen::get_width");
        SPDLOG_DEBUG("get UnityEngine.Screen::get_height address: {}", fmt::ptr(Screen$$get_width));
        // 使用Unity游戏内的导出方法 获取屏幕宽高
        if (Screen$$get_height && Screen$$get_width)
        {
            SPDLOG_INFO("Screen size is {}x{}", Screen$$get_width(), Screen$$get_height());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    } while (!Screen$$get_height && !Screen$$get_width);

    InitResolveFunc(Time$$set_timeScale, "UnityEngine.Time::set_timeScale");
    InitResolveFunc(Time$$get_timeScale, "UnityEngine.Time::get_timeScale");
    SPDLOG_DEBUG("get get_timeScale: {}", fmt::ptr(Time$$get_timeScale));
    SPDLOG_DEBUG("get set_timeScale: {}", fmt::ptr(Time$$set_timeScale));
    if (Time$$get_timeScale && Time$$set_timeScale)
    {
        SPDLOG_INFO("Time scale is {}", Time$$get_timeScale());
        Time$$set_timeScale(10.0f);
        SPDLOG_INFO("Time scale set {}", Time$$get_timeScale());
    }

    InitResolveFunc(Time$$get_deltaTime, "UnityEngine.Time::get_fixedDeltaTime");
    SPDLOG_DEBUG("get get_deltaTime: {}", fmt::ptr(Time$$get_deltaTime));

    InitResolveFunc(Time$$set_fixedDeltaTime, "UnityEngine.Time::set_fixedDeltaTime");
    InitResolveFunc(Time$$get_fixedDeltaTime, "UnityEngine.Time::get_fixedDeltaTime");
    SPDLOG_DEBUG("get get_fixedDeltaTime: {}", fmt::ptr(Time$$get_fixedDeltaTime));
    SPDLOG_DEBUG("get set_fixedDeltaTime: {}", fmt::ptr(Time$$set_fixedDeltaTime));
    if (Time$$get_fixedDeltaTime && Time$$set_fixedDeltaTime)
    {
        auto value = Time$$get_fixedDeltaTime();
        SPDLOG_INFO("fixed delta time is {}", value);
        Time$$set_fixedDeltaTime(value);
        SPDLOG_INFO("fixed delta time set {}", Time$$get_fixedDeltaTime());
    }
}

YY_API void example_agent_main(const gchar *data, gboolean *stay_resident)
{
    if (data)
    {
        try
        {
            json json = json::parse(data);

            server_port = json["port"].get<int>();
            g_speed = json["speed"].get<int>();
            pid = json["pid"].get<int>();
            process_name = json["name"].get<std::string>();
        }
        catch (const json::exception &e)
        {
            SPDLOG_ERROR("parse args error: {}", e.what());
            return;
        }
    }
    // SPDLOG_INFO("example_agent_main(\"{}\")", data);
    SPDLOG_INFO("service port: {}", server_port);
    SPDLOG_INFO("speed: {}", g_speed);

    /* We don't want to our library to be unloaded after we return. */
    *stay_resident = TRUE;

    // GumInterceptor *interceptor = gum_interceptor_obtain();
    // // listener = my_callback_listener_new();
    //
    // gum_interceptor_begin_transaction(interceptor);
    // gpointer open_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "open"));
    // gum_interceptor_replace(interceptor, open_origin_address, reinterpret_cast<gpointer>(&open_hook), NULL, NULL);
    // gpointer gettimeofday_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "gettimeofday"));
    // gum_interceptor_replace(interceptor, gettimeofday_origin_address, reinterpret_cast<gpointer>(&gettimeofday_hook), NULL, NULL);
    // gpointer clock_gettime_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "clock_gettime"));
    // gum_interceptor_replace(interceptor, clock_gettime_origin_address, reinterpret_cast<gpointer>(&clock_gettime_hook), NULL, NULL);
    // gum_interceptor_end_transaction(interceptor);

    gp_run = std::make_shared<std::thread>([&]()
                                           {
                        SPDLOG_INFO("work thread started.");
                        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                        pthread_create_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "pthread_create"));
                        gettimeofday_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "gettimeofday"));
                        clock_gettime_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "clock_gettime"));
                        
                        // gpointer lua = nullptr;
                        SPDLOG_INFO("start check piling.");
                        SPDLOG_INFO("start enumerate modlues.");
                        do {
                            gum_process_enumerate_modules(foundModule, nullptr);
                            // uinty3d il2cpp
                            if (il2cppAddress)
                            {
                                SPDLOG_INFO("get il2cpp address: {:#08x}", il2cppAddress);
                                break;
                            }
                            // cocos
                            if (waitCocosSoLoaded) {
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update1));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update2));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_normal_update3));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update1));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update2));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update3));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update4));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_special_update5));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_jni_nativeRender));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_jni_loadNativeCode));
                                SPDLOG_INFO("get cocos update address: {}", fmt::ptr(cocos_jni_onCreate));
                                break;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        } while (true);
                        
                        // 动态库已经完全加载
                        if (il2cppAddress)
                        {
                            initUnity3Dil2cpp();
                        }
                        
                        if (waitCocosSoLoaded)
                        {
                            GumInterceptor *interceptor  = gum_interceptor_obtain();
                            gum_interceptor_replace(interceptor, gettimeofday_origin_address, reinterpret_cast<gpointer>(&gettimeofday_hook), NULL, NULL);
                            gum_interceptor_replace(interceptor, clock_gettime_origin_address, reinterpret_cast<gpointer>(&clock_gettime_hook), NULL, NULL);

                            gum_interceptor_begin_transaction(interceptor);
                            if (cocos_normal_update1)
                            {
                                COCOS_NORMAL_UPDATE = reinterpret_cast<cocos2dx_update_fun>(cocos_normal_update1);
                                gum_interceptor_replace(interceptor, cocos_normal_update1, reinterpret_cast<gpointer>(&cocos_normal_update_hook), NULL, NULL);
                            }
                            else if (cocos_normal_update2)
                            {
                                isCocosCreator = (cocos_special_update3 == nullptr && cocos_special_update4 == nullptr && cocos_special_update5 == nullptr);
                                COCOS_NORMAL_UPDATE = reinterpret_cast<cocos2dx_update_fun>(cocos_normal_update2);
                                gum_interceptor_replace(interceptor, cocos_normal_update2, reinterpret_cast<gpointer>(&cocos_normal_update_hook), NULL, NULL);
                            }

                            if (cocos_special_update1)
                            {
                                COCOS_SPECIAL_UPDATE_ONE = reinterpret_cast<cocos2dx_update_fun>(cocos_special_update1);
                                gum_interceptor_replace(interceptor, cocos_special_update1, reinterpret_cast<gpointer>(&cocos_special_update_hook_one), NULL, NULL);
                            }
                            if (cocos_special_update2)
                            {
                                COCOS_SPECIAL_UPDATE_TWO = reinterpret_cast<cocos2dx_update_fun2>(cocos_special_update2);
                                gum_interceptor_replace(interceptor, cocos_special_update2, reinterpret_cast<gpointer>(&cocos_special_update_hook_two), NULL, NULL);
                            }
                            if (cocos_special_update3)
                            {
                                COCOS_SPECIAL_UPDATE_THREE = reinterpret_cast<cocos2dx_update_fun2>(cocos_special_update3);
                                gum_interceptor_replace(interceptor, cocos_special_update3, reinterpret_cast<gpointer>(&cocos_special_update_hook_three), NULL, NULL);
                            }
                            if (cocos_special_update4)
                            {
                                COCOS_SPECIAL_UPDATE_FOUR = reinterpret_cast<cocos2dx_update_fun3>(cocos_special_update4);
                                gum_interceptor_replace(interceptor, cocos_special_update4, reinterpret_cast<gpointer>(&cocos_special_update_hook_four), NULL, NULL);
                            }
                            if (cocos_special_update5)
                            {
                                COCOS_SPECIAL_UPDATE_FIVE = reinterpret_cast<cocos2dx_update_fun2>(cocos_special_update5);
                                gum_interceptor_replace(interceptor, cocos_special_update5, reinterpret_cast<gpointer>(&cocos_special_update_hook_five), NULL, NULL);
                            }

                            if (cocos_jni_loadNativeCode)
                            {

                            }
                            if (cocos_jni_onCreate)
                            {

                            }
                            
                            gum_interceptor_end_transaction(interceptor);
                        }

                        // 进入主循环
                        int64_t last_check = getUnixTimestamp(), now;
                        httplib::Client client("localhost", server_port);
                        std::string path = fmt::format("/status?name={}", process_name);
                        json req_body = {{"name", process_name}, {"speed", g_speed}, {"pid", pid}};
                        std::string body = req_body.dump();
                        while(true) {
                            now = getUnixTimestamp();
                            if (now - last_check > 900) {
                                last_check = now;
                                if (auto res = client.Post(path, body, "application/json")) {
                                    try
                                    {
                                        json json = json::parse(res->body);

                                        g_speed = json["speed"].get<int>();
                                        req_body["speed"] = g_speed;
                                        body = req_body.dump();
                                    }
                                    catch (const json::exception &e)
                                    {
                                        SPDLOG_ERROR("parse status error: {}", e.what());
                                    }
                                }
                            }
                            // LOGD("seconds");
                            if (Time$$set_timeScale) {
                                Time$$set_timeScale(g_speed);
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        } });
    gp_run->join();

    // // g_object_unref (listener);
    // // g_object_unref (interceptor);
    // // gum_deinit_embedded();
}

// static int open_hook(const char *path, int oflag, ...)
// {
//     LOGD("open(\"%s\", 0x%x)", path, oflag);

//     return open(path, oflag);
// }

static int pthread_create_hook(pthread_t*ptr, const pthread_attr_t*attr, void*func, void*func_data)
{
    return pthread_create((pthread_t*)ptr, (const pthread_attr_t*)attr, (void * (*)(void *))func, func_data);
}

static int gettimeofday_hook(struct timeval *tv, struct timezone *tz)
{
    int result = gettimeofday(tv, tz);
    // LOGD("gettimeofday %p, %p %d", tv, tz, result);
    // if (result == 0 && tv != NULL)
    if (g_modify_time)
    {
        if (g_tv.tv_sec == 0)
        {
            g_tv.tv_sec = tv->tv_sec;
            g_tv.tv_usec = tv->tv_usec;
        }
        tv->tv_sec = g_tv.tv_sec + (tv->tv_sec - g_tv.tv_sec) * g_speed;
        tv->tv_usec = g_tv.tv_usec + (tv->tv_usec - g_tv.tv_usec) * g_speed;

        // LOGD("gettimeofday %ld -> %ld,  %ld -> %ld", g_tv.tv_sec, tv->tv_sec, g_tv.tv_usec, tv->tv_usec);
    }
    g_modify_time = false;

    return result;
}

static int clock_gettime_hook(clockid_t clock, struct timespec *ts)
{
    int result = clock_gettime(clock, ts);
    // LOGD("clock_gettime %p, %p %d", &clock, ts, result);
    // if (result == 0 && ts != NULL)
    if (g_modify_time)
    {
        if (g_ts.tv_sec == 0)
        {
            g_ts.tv_sec = ts->tv_sec;
            g_ts.tv_nsec = ts->tv_nsec;
        }
        ts->tv_sec = g_ts.tv_sec + (ts->tv_sec - g_ts.tv_sec) * g_speed;
        ts->tv_nsec = g_ts.tv_nsec + (ts->tv_nsec - g_ts.tv_nsec) * g_speed;

        // LOGD("clock_gettime time %ld -> %ld", g_ts.tv_sec, ts->tv_sec);
    }
    g_modify_time = false;

    return result;
}

static void cocos_normal_update_hook(void *v, float dt)
{
    if (isCocosCreator)
    {
        g_modify_time = true;
    }
    else
    {
        dt = dt * g_speed;

        float repeatTime = 0.0;

        while (repeatTime < g_speed)
        {
            repeatTime = repeatTime + 0.5;
            COCOS_NORMAL_UPDATE(v, dt);
        }

        COCOS_NORMAL_UPDATE(v, dt);
    }
}

static void cocos_special_update_hook_one(void *v, float dt)
{
    dt = dt * g_speed;
    COCOS_SPECIAL_UPDATE_ONE(v, dt);
}

static void *cocos_special_update_hook_two(void *v, float dt)
{
    dt = dt * g_speed;
    return COCOS_SPECIAL_UPDATE_TWO(v, dt);
}

static void *cocos_special_update_hook_three(void *v, float dt)
{
    dt = dt * g_speed;
    return COCOS_SPECIAL_UPDATE_THREE(v, dt);
}

static bool cocos_special_update_hook_four(void *__hidden, float radio)
{
    SPDLOG_DEBUG("speed_step = {}", radio);

    radio = radio * g_speed;

    return COCOS_SPECIAL_UPDATE_FOUR(__hidden, radio);
}

static void *cocos_special_update_hook_five(void *envirenment, float delater)
{
    SPDLOG_DEBUG("delater = {}", delater);

    return COCOS_SPECIAL_UPDATE_FIVE(envirenment, delater);
}

__attribute__((constructor)) void constructor_main()
{
    LOGD("YYCheat");
    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>("YY-INJECT");
    auto logger = std::make_shared<spdlog::logger>("InjectCheat", spdlog::sinks_init_list{android_sink});
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::debug);

    gum_init_embedded();
    SPDLOG_DEBUG("frida-gum init");
}

__attribute__((destructor)) void destructor_function(void)
{
    gum_deinit_embedded();
}
