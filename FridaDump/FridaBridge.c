#include "FridaBridge.h"
#include "frida-core.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

static FridaDeviceManager *g_manager = NULL;
static FridaDevice        *g_device  = NULL;
static FridaSession       *g_session = NULL;
static FridaScript        *g_script  = NULL;
static GMainLoop          *g_loop    = NULL;
static GThread            *g_thread  = NULL;

static FDBMessageCallback  g_cb  = NULL;
static void               *g_ctx = NULL;
static guint               g_pid = 0;



static gpointer loop_thread_func(gpointer data) {
    (void)data;
    g_main_loop_run(g_loop);
    return NULL;
}


static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}
static double g_t0 = 0;
static void mark(const char *what) {
    fprintf(stderr, "[bridge %6.0fms] %s\n", now_ms() - g_t0, what);
    fflush(stderr);
}

static void set_error(char **out, const char *msg) {
    if (out) *out = strdup(msg ? msg : "unknown error");
}

static void take_gerror(char **out, GError *error) {
    if (error) {
        if (out) *out = strdup(error->message);
        g_error_free(error);
    }
}

static void append_json_string(GString *s, const char *v) {
    g_string_append_c(s, '"');
    if (v) {
        for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
            switch (*p) {
                case '"':  g_string_append(s, "\\\""); break;
                case '\\': g_string_append(s, "\\\\"); break;
                case '\n': g_string_append(s, "\\n");  break;
                case '\r': g_string_append(s, "\\r");  break;
                case '\t': g_string_append(s, "\\t");  break;
                default:
                    if (*p < 0x20) g_string_append_printf(s, "\\u%04x", *p);
                    else g_string_append_c(s, (char)*p);
            }
        }
    }
    g_string_append_c(s, '"');
}

static FridaDevice *acquire_device(char **errmsg) {
    if (g_device != NULL) return g_device;

    GError *error = NULL;
    g_device = frida_device_manager_find_device_by_type_sync(
        g_manager, FRIDA_DEVICE_TYPE_USB, 5000, NULL, &error);
    if (error != NULL) {
        take_gerror(errmsg, error);
        g_device = NULL;
    }
    return g_device;
}

/** 设备掉线后清掉缓存，下次重新枚举 */
static void drop_device(void) {
    if (g_device) {
        g_object_unref(g_device);
        g_device = NULL;
    }
}

static void on_script_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
    (void)script;
    (void)user_data;
    mark("on_message hit");
    if (g_cb == NULL) { mark("no callback"); return; }

    const uint8_t *bytes = NULL;
    size_t len = 0;
    if (data != NULL) bytes = g_bytes_get_data(data, &len);
    g_cb(message, bytes, len, g_ctx);
}



int fdb_init(void) {
    if (g_manager != NULL) return 0;

    frida_init();
    g_loop = g_main_loop_new(NULL, FALSE);
    g_thread = g_thread_new("frida-loop", loop_thread_func, NULL);
    g_manager = frida_device_manager_new();
    return 0;
}

void fdb_shutdown(void) {
    fdb_teardown();
    drop_device();
    if (g_loop != NULL) {
        g_main_loop_quit(g_loop);
        g_main_loop_unref(g_loop);
        g_loop = NULL;
    }
    if (g_thread != NULL) {
        g_thread_join(g_thread);
        g_thread = NULL;
    }
    if (g_manager != NULL) {
        g_object_unref(g_manager);
        g_manager = NULL;
    }
}

char *fdb_device_name(void) {
    if (g_manager == NULL) fdb_init();
    char *err = NULL;
    FridaDevice *dev = acquire_device(&err);
    if (err) free(err);
    if (dev == NULL) return NULL;
    return strdup(frida_device_get_name(dev));
}

char *fdb_enumerate_apps(char **errmsg) {
    if (g_manager == NULL) fdb_init();

    FridaDevice *dev = acquire_device(errmsg);
    if (dev == NULL) return NULL;

    GError *error = NULL;
    FridaApplicationList *apps = frida_device_enumerate_applications_sync(dev, NULL, NULL, &error);
    if (error != NULL) {
        take_gerror(errmsg, error);
        drop_device();  /* 旧句柄多半失效了，逼下次重连 */
        return NULL;
    }

    GString *out = g_string_new("[");
    gint count = frida_application_list_size(apps);
    for (gint i = 0; i < count; i++) {
        FridaApplication *app = frida_application_list_get(apps, i);
        if (i > 0) g_string_append_c(out, ',');
        g_string_append(out, "{\"name\":");
        append_json_string(out, frida_application_get_name(app));
        g_string_append(out, ",\"identifier\":");
        append_json_string(out, frida_application_get_identifier(app));
        g_string_append_printf(out, ",\"pid\":%u}", frida_application_get_pid(app));
        g_object_unref(app);
    }
    g_string_append_c(out, ']');

    g_object_unref(apps);

    char *result = out->str;
    g_string_free(out, FALSE);
    return result;
}

/** 结束设备上正在运行的同名 App（运行态 attach 会挂死） */
static void kill_running_instance(FridaDevice *dev, const char *bundle_id) {
    GError *error = NULL;
    FridaApplicationList *apps = frida_device_enumerate_applications_sync(dev, NULL, NULL, &error);
    if (error != NULL) { g_error_free(error); return; }

    gint n = frida_application_list_size(apps);
    for (gint i = 0; i < n; i++) {
        FridaApplication *app = frida_application_list_get(apps, i);
        const gchar *ident = frida_application_get_identifier(app);
        guint pid = frida_application_get_pid(app);
        g_object_unref(app);
        if (pid != 0 && ident != NULL && strcmp(ident, bundle_id) == 0) {
            frida_device_kill_sync(dev, pid, NULL, NULL);
            g_usleep(800 * 1000);
            break;
        }
    }
    g_object_unref(apps);
}


int fdb_start_dump(const char *bundle_id,
                   const char *script,
                   FDBMessageCallback cb,
                   void *ctx,
                   char **errmsg) {
    if (g_manager == NULL) fdb_init();

    g_t0 = now_ms();
    mark("start");
    FridaDevice *dev = acquire_device(errmsg);
    if (dev == NULL) { mark("no device"); return -1; }
    mark("device ok");

    GError *error = NULL;

    /* 1. 结束已在运行的实例（运行态 attach 会挂死） */
    if (g_pid != 0) {
        frida_device_kill_sync(dev, g_pid, NULL, &error);
        if (error) { g_error_free(error); error = NULL; }
        g_pid = 0;
    }

    /* 1.5 结束设备上已在运行的实例 */
    kill_running_instance(dev, bundle_id);
    mark("kill done");

    /* 2. spawn（挂起态） */
    g_pid = frida_device_spawn_sync(dev, bundle_id, NULL, NULL, &error);
    mark("spawn done");
    if (error != NULL) {
        take_gerror(errmsg, error);
        drop_device();
        return -2;
    }

    /* 3. attach */
    g_session = frida_device_attach_sync(dev, g_pid, NULL, NULL, &error);
    mark("attach done");
    if (error != NULL) {
        take_gerror(errmsg, error);
        frida_device_kill_sync(dev, g_pid, NULL, NULL);
        g_pid = 0;
        return -3;
    }

    /* 4. 注入脚本（必须在 resume 之前） */
    g_script = frida_session_create_script_sync(g_session, script, NULL, NULL, &error);
    mark("script created");
    if (error != NULL) {
        take_gerror(errmsg, error);
        fdb_teardown();
        return -4;
    }

    g_cb = cb;
    g_ctx = ctx;
    g_signal_connect(g_script, "message", G_CALLBACK(on_script_message), NULL);

    frida_script_load_sync(g_script, NULL, &error);
    mark("script loaded");
    if (error != NULL) {
        take_gerror(errmsg, error);
        fdb_teardown();
        return -5;
    }

    /* 5. 放行 */
    frida_device_resume_sync(dev, g_pid, NULL, &error);
    mark("resumed");
    if (error != NULL) {
        take_gerror(errmsg, error);
        fdb_teardown();
        return -6;
    }

    return 0;
}

void fdb_post(const char *json) {
    if (g_script == NULL) return;
    frida_script_post(g_script, json, NULL);
}

void fdb_teardown(void) {
    g_cb = NULL;
    g_ctx = NULL;

    if (g_script != NULL) {
        g_object_unref(g_script);
        g_script = NULL;
    }
    if (g_session != NULL) {
        if (!frida_session_is_detached(g_session)) {
            frida_session_detach_sync(g_session, NULL, NULL);
        }
        g_object_unref(g_session);
        g_session = NULL;
    }
    if (g_pid != 0 && g_device != NULL) {
        frida_device_kill_sync(g_device, g_pid, NULL, NULL);
    }
    g_pid = 0;
}
