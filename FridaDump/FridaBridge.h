#ifndef FRIDA_BRIDGE_H
#define FRIDA_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 消息回调：json 为 frida 的 message 字符串，data/len 为二进制负载（可为 NULL） */
typedef void (*FDBMessageCallback)(const char *json, const uint8_t *data, size_t len, void *ctx);

int   fdb_init(void);
void  fdb_shutdown(void);

/* 返回 JSON 字符串，调用方负责 free()；失败返回 NULL */
char *fdb_enumerate_apps(char **errmsg);
char *fdb_device_name(void);

/* 先结束已有实例，再 spawn -> attach -> 注入 -> resume -> 发 dump 指令 */
int   fdb_start_dump(const char *bundle_id,
                     const char *script,
                     FDBMessageCallback cb,
                     void *ctx,
                     char **errmsg);

void  fdb_post(const char *json);
void  fdb_teardown(void);

#ifdef __cplusplus
}
#endif

#endif /* FRIDA_BRIDGE_H */
