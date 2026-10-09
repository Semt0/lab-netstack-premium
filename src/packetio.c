#include "packetio.h"
#include "device.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>

static int frameError(const char *message, int error) {
    fprintf(stderr, "sendFrame: %s\n", message);
    errno = error;
    return -1;
}

static frameReceiveCallback receive_callback = NULL;

int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id) {
    if (len < 0) {
        return frameError("payload length must not be negative", EINVAL);
    }
    if (len > 1500) {
        return frameError("payload exceeds the 1500-byte limit", EMSGSIZE);
    }
    if (len > 0 && buf == NULL) {
        return frameError("non-empty payload requires a buffer", EINVAL);
    }
    if (destmac == NULL) {
        return frameError("destination MAC is NULL", EINVAL);
    }
    if (ethtype < 0x0600 || ethtype > 0xffff) {
        return frameError("EtherType must be between 0x0600 and 0xffff", EINVAL);
    }

    pcap_t *handle = getDeviceHandle(id);
    if (handle == NULL) {
        return frameError("device ID is not registered", ENODEV);
    }
    unsigned char srcmac[6];
    if (getDeviceMAC(id, srcmac) != 0) {
        return frameError("cannot obtain the cached source MAC", EIO);
    }

    size_t frame_len = 14 + (size_t)len;
    if (frame_len < 60) {
        frame_len = 60;
    }

    unsigned char *frame = calloc(frame_len, 1);
    if (frame == NULL) {
        return frameError("cannot allocate frame buffer", ENOMEM);
    }
    memcpy(frame, destmac, 6);
    memcpy(frame + 6, srcmac, 6);
    frame[12] = (unsigned char)((ethtype >> 8) & 0xff);
    frame[13] = (unsigned char)(ethtype & 0xff);
    if (len > 0) memcpy(frame + 14, buf, (size_t)len);

    int sent = pcap_inject(handle, frame, frame_len);
    free(frame);
    if (sent < 0) {
        return frameError(pcap_geterr(handle), EIO);
    }
    if ((size_t)sent != frame_len) {
        return frameError("incomplete send", EIO);
    }
    return 0;
}

static int receiveError(const char *message, int error) {
    fprintf(stderr, "receiveFrames: %s\n", message);
    errno = error;
    return -1;
}

int receiveFrames(int id, int count) {
    if (count <= 0) {
        return receiveError("count must be positive", EINVAL);
    }
    if (receive_callback == NULL) {
        return receiveError("no frame callback is registered", EINVAL);
    }
    pcap_t *handle = getDeviceHandle(id);
    if (handle == NULL) {
        return receiveError("device ID is not registered", ENODEV);
    }
    int link_type = pcap_datalink(handle);
    if (link_type < 0) {
        return receiveError(pcap_geterr(handle), EIO);
    }
    if (link_type != DLT_EN10MB) {
        return receiveError("capture device does not provide Ethernet frames", EPROTONOSUPPORT);
    }

    /* Keep this call's callback stable, even if it changes registration. */
    frameReceiveCallback callback = receive_callback;
    int processed = 0;
    while (processed < count) {
        struct pcap_pkthdr *header = NULL;
        const unsigned char *data = NULL;
        int result = pcap_next_ex(handle, &header, &data);
        switch (result) {
        case 0:
            continue;
        case PCAP_ERROR_BREAK:
            return receiveError("capture ended before count was reached", EPIPE);
        case 1: {
            if (header == NULL || data == NULL) {
                return receiveError("capture returned missing frame data", EIO);
            }
            if (header->caplen < 14 || header->caplen < header->len) {
                continue;
            }
            if (header->caplen > INT_MAX) {
                return receiveError("captured frame exceeds callback length range", EMSGSIZE);
            }
            if (callback(data, (int)header->caplen, id) != 0) {
                return receiveError("frame callback reported failure", EIO);
            }
            processed++;
            break;
        }
        default:
            return receiveError(pcap_geterr(handle), EIO);
        }
    }
    return 0;
}

int setFrameReceiveCallback(frameReceiveCallback callback) {
    receive_callback = callback;
    return 0;
}
