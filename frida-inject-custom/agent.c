#include <fcntl.h>
#include <frida-gum.h>

int g_speed = 15.0;
struct timeval g_tv = {0, 0};
struct timespec g_ts = {0, 0};

static int replacement_open(const char *path, int oflag, ...);
static int gettimeofday_hook(struct timeval* tv, struct timezone* tz);
static int clock_gettime_hook(clockid_t clock, struct timespec* ts);

void example_agent_main(const gchar *data, gboolean *stay_resident)
{
    GumInterceptor *interceptor;

    /* We don't want to our library to be unloaded after we return. */
    *stay_resident = TRUE;

    gum_init_embedded();

    g_printerr("example_agent_main()\n");

    interceptor = gum_interceptor_obtain();

    /* Transactions are optional but improve performance with multiple hooks. */
    gum_interceptor_begin_transaction(interceptor);

    gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "open"), &replacement_open, NULL, NULL);
    gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "gettimeofday"), &gettimeofday_hook, NULL, NULL);
    gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "clock_gettime"), &clock_gettime_hook, NULL, NULL);
    /*
     * ^
     * |
     * This is using replace(), but there's also attach() which can be used to hook
     * functions without any knowledge of argument types, calling convention, etc.
     * It can even be used to put a probe in the middle of a function.
     */

    gum_interceptor_end_transaction(interceptor);
}

static int replacement_open(const char *path, int oflag, ...)
{
    g_printerr("open(\"%s\", 0x%x)\n", path, oflag);

    return open(path, oflag);
}

static int gettimeofday_hook(struct timeval* tv, struct timezone* tz)
{
    int result = gettimeofday(tv, tz);
    // g_printerr("gettimeofday %p, %p %d", tv, tz, result);
    if (result == 0 && tv != NULL)
    {
        if (g_tv.tv_sec == 0) {
            g_tv.tv_sec = tv->tv_sec;
            g_tv.tv_usec = tv->tv_usec;
        }
        tv->tv_sec = g_tv.tv_sec + (tv->tv_sec - g_tv.tv_sec) * g_speed;
        tv->tv_usec = g_tv.tv_usec + (tv->tv_usec - g_tv.tv_usec) * g_speed;

        g_printerr("gettimeofday %ld -> %ld,  %ld -> %ld", g_tv.tv_sec, tv->tv_sec, g_tv.tv_usec, tv->tv_usec);
    }

    return result;
}

static int clock_gettime_hook(clockid_t clock, struct timespec* ts)
{
    int result = clock_gettime(clock, ts);
    // g_printerr("clock_gettime %p, %p %d", &clock, ts, result);
    if (result == 0 && ts != NULL)
    {
        if (g_ts.tv_sec == 0) {
            g_ts.tv_sec = ts->tv_sec;
            g_ts.tv_nsec = ts->tv_nsec;
        }
        ts->tv_sec = g_ts.tv_sec + (ts->tv_sec - g_ts.tv_sec) * g_speed;
        ts->tv_nsec = g_ts.tv_nsec + (ts->tv_nsec - g_ts.tv_nsec) * g_speed;

        g_printerr("clock_gettime time %ld -> %ld", g_ts.tv_sec, ts->tv_sec);
    }

    return result;
}
