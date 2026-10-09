#include "device.h"
#include <stdio.h>

#define CHECK(condition) do {                              \
    if (!(condition)) {                                    \
        fprintf(stderr, "FAIL at line %d: %s\n",            \
                __LINE__, #condition);                     \
        clearDevices();                                    \
        return 1;                                          \
    }                                                      \
    printf("PASS: %s\n", #condition);                       \
} while (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *name = argv[1];

    /* 未注册时应该找不到。 */
    CHECK(findDevice(name) == -1);

    /* 正常注册，并能通过名称找到同一个 ID。 */
    int id = addDevice(name);
    CHECK(id >= 0);
    CHECK(findDevice(name) == id);
    CHECK(getDeviceHandle(id) != NULL);
    CHECK(getDeviceHandle(-1) == NULL);
    CHECK(getDeviceHandle(16) == NULL);

    /* 重复注册应该返回原来的 ID。 */
    CHECK(addDevice(name) == id);

    /* 错误输入应该被拒绝，且不影响已有设备。 */
    CHECK(addDevice(NULL) == -1);
    CHECK(addDevice("") == -1);
    CHECK(findDevice(NULL) == -1);
    CHECK(findDevice("") == -1);
    CHECK(findDevice("pt1_missing0") == -1);
    CHECK(addDevice("pt1_missing0") == -1);
    CHECK(findDevice(name) == id);

    /* 清理后查找失败；重复清理应该安全。 */
    clearDevices();
    CHECK(getDeviceHandle(id) == NULL);
    CHECK(findDevice(name) == -1);
    clearDevices();

    /* 清理后能重新注册。 */
    int new_id = addDevice(name);
    CHECK(new_id >= 0);
    CHECK(findDevice(name) == new_id);

    clearDevices();
    puts("All PT1 checks passed.");
    return 0;
}
