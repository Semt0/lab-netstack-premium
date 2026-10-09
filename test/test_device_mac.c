#include "device.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        clearDevices(); \
        return 1; \
    } \
    printf("PASS: %s\n", #condition); \
} while (0)

/* Independent reference: read the MAC exposed by Linux sysfs. */
static int read_reference_mac(const char *name, unsigned char mac[6]) {
    char path[256];
    if (strchr(name, '/') != NULL) return -1;
    int n = snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) return -1;
    unsigned int bytes[6];
    int count = fscanf(fp, "%x:%x:%x:%x:%x:%x",
                       &bytes[0], &bytes[1], &bytes[2],
                       &bytes[3], &bytes[4], &bytes[5]);
    fclose(fp);
    if (count != 6) return -1;
    for (int i = 0; i < 6; ++i) {
        if (bytes[i] > 255) return -1;
        mac[i] = (unsigned char)bytes[i];
    }
    return 0;
}

static int open_fd_count(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) ++count;
    }
    closedir(dir);
    return count;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Ethernet-interface>\n", argv[0]);
        return 1;
    }
    const char *name = argv[1];
    unsigned char expected[6];
    CHECK(read_reference_mac(name, expected) == 0);
    clearDevices();
    CHECK(findDevice(name) == -1);
    int id = addDevice(name);
    CHECK(id >= 0);
    CHECK(findDevice(name) == id);
    CHECK(getDeviceHandle(id) != NULL);
    CHECK(addDevice(name) == id);

    /* Canary bytes catch writes beyond the six-byte output. */
    unsigned char guarded[8];
    memset(guarded, 0xa5, sizeof(guarded));
    CHECK(getDeviceMAC(id, guarded + 1) == 0);
    CHECK(guarded[0] == 0xa5 && guarded[7] == 0xa5);
    CHECK(memcmp(guarded + 1, expected, 6) == 0);
    printf("Verified MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           expected[0], expected[1], expected[2],
           expected[3], expected[4], expected[5]);

    /* Changing the caller's copy must not change the cache. */
    memset(guarded + 1, 0, 6);
    CHECK(getDeviceMAC(id, guarded + 1) == 0);
    CHECK(memcmp(guarded + 1, expected, 6) == 0);
    CHECK(getDeviceMAC(id, NULL) == -1);
    CHECK(getDeviceMAC(-1, guarded + 1) == -1);
    CHECK(getDeviceMAC(1000000, guarded + 1) == -1);
    CHECK(addDevice(NULL) == -1);
    CHECK(addDevice("") == -1);
    CHECK(addDevice("pt1_missing0") == -1);
    CHECK(findDevice("pt1_missing0") == -1);

    /* lo opens for capture but must fail Ethernet MAC validation. */
    CHECK(addDevice("lo") == -1);
    CHECK(findDevice("lo") == -1);
    CHECK(findDevice(name) == id);
    CHECK(getDeviceMAC(id, guarded + 1) == 0);
    CHECK(memcmp(guarded + 1, expected, 6) == 0);

    clearDevices();
    CHECK(findDevice(name) == -1);
    CHECK(getDeviceHandle(id) == NULL);
    CHECK(getDeviceMAC(id, guarded + 1) == -1);
    clearDevices();

    /* Repeated failed registrations must not retain open handles. */
    int fd_before = open_fd_count();
    CHECK(fd_before >= 0);
    for (int i = 0; i < 20; ++i) CHECK(addDevice("lo") == -1);
    CHECK(open_fd_count() == fd_before);

    /* Verify reuse after failures and cleanup. */
    for (int i = 0; i < 5; ++i) {
        int next_id = addDevice(name);
        CHECK(next_id >= 0);
        CHECK(getDeviceMAC(next_id, guarded + 1) == 0);
        CHECK(memcmp(guarded + 1, expected, 6) == 0);
        clearDevices();
    }
    CHECK(open_fd_count() == fd_before);
    puts("All device/MAC integration checks passed.");
    return 0;
}
