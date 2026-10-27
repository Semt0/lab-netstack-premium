/**
* @file device.h
* @brief Library supporting network device management.
*/

#ifndef DEVICE_H
#define DEVICE_H
#include <pcap.h>
#include <netinet/in.h>

/**
* Add a device to the library for sending/receiving packets.
*
* @param device Name of network device to send/receive packet on.
* @return A non -negative _device -ID_ on success , -1 on error.
*/
int addDevice(const char* device);

/**
* Find a device added by ‘addDevice ‘.
*
* @param device Name of the network device.
* @return A non -negative _device -ID_ on success , -1 if no such device
* was found.
*/
int findDevice(const char* device);

// 返回已注册设备的名称
const char* getDeviceName(int id);

void clearDevices(void);

typedef enum {
    DEVICE_RX,
    DEVICE_TX
} DeviceHandleType;

/* Borrow the selected handle; invalid IDs/directions return NULL.
 * RX is for the receiving thread. TX is for sending; sendFrame serializes
 * injection. Direct TX users need their own coordination with sendFrame.
 * Stop all users before clearDevices().
 */
pcap_t *getDeviceHandle(int id, DeviceHandleType direction);

int getDeviceMAC(int id, unsigned char mac[6]);

/* Copy the first IPv4 address found when addDevice registered the interface.
 * The address stays in network byte order. Returns 0 on success, -1 for an
 * invalid ID/output pointer or no cached IPv4 address. Configure addresses
 * before addDevice; clear and register again to refresh the cached address.
 */
int getDeviceip(int id, struct in_addr* ip);

// 判断是否为任意已注册接口的缓存 IPv4 地址，返回 1 或 0。
int isLocalIP(const struct in_addr ip);

#endif
