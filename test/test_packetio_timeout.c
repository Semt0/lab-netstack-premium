#include "packetio.h"
#include "device.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Real pipe readiness, poll and monotonic clock; no network or privileges. */
static int channel[2];
static int nonblock, callbacks, callback_fails, no_fd;
static int reads, force_capture_error, mode_failure, continuous_event, slow_callback;
static unsigned char token, frame[60];
static struct pcap_pkthdr header;
static volatile sig_atomic_t signals;

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #condition, errno); \
    exit(1); } } while (0)

pcap_t *getDeviceHandle(int id, DeviceHandleType direction) { return id == 0 && direction == DEVICE_RX ? (pcap_t *)&token : NULL; }
int getDeviceMAC(int id, unsigned char mac[6]) { (void)id; (void)mac; return -1; }
int pcap_datalink(pcap_t *p) { (void)p; return DLT_EN10MB; }
int pcap_getnonblock(pcap_t *p, char *errbuf) {
    (void)p; (void)errbuf; return nonblock;
}
int pcap_setnonblock(pcap_t *p, int value, char *errbuf) {
    (void)p;
    if (mode_failure == (value ? 1 : 2)) {
        strcpy(errbuf, "simulated mode failure");
        return PCAP_ERROR;
    }
    nonblock = value;
    return 0;
}
int pcap_get_selectable_fd(pcap_t *p) { (void)p; return no_fd ? -1 : channel[0]; }
const struct timeval *pcap_get_required_select_timeout(pcap_t *p) {
    (void)p; return NULL;
}
char *pcap_geterr(pcap_t *p) { (void)p; return "simulated capture error"; }
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const unsigned char **data) {
    (void)p;
    CHECK(nonblock == 1);
    ++reads;
    if (force_capture_error) return PCAP_ERROR;
    char event = (char)continuous_event;
    if (!continuous_event) {
        ssize_t count = read(channel[0], &event, 1);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
        CHECK(count == 1);
    }
    if (event == 'B') return PCAP_ERROR_BREAK;
    header.caplen = event == 'S' ? 13 : sizeof(frame);
    header.len = sizeof(frame);
    *h = &header;
    *data = frame;
    return 1;
}
static int on_frame(const void *buf, int len, int id) {
    CHECK(buf == frame && len == 60 && id == 0);
    CHECK(nonblock == 1); /* the capture loop remains nonblocking */
    ++callbacks;
    if (slow_callback) usleep(60000);
    return callback_fails ? -1 : 0;
}
static double milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0;
}
static void reset(void) {
    char discarded;
    while (read(channel[0], &discarded, 1) == 1) {}
    nonblock = callbacks = callback_fails = no_fd = 0;
    reads = force_capture_error = mode_failure = continuous_event = slow_callback = 0;
    CHECK(setFrameReceiveCallback(on_frame) == 0);
}
static void queue(const char *events) {
    size_t len = strlen(events);
    CHECK(write(channel[1], events, len) == (ssize_t)len);
}
static void wait_child(pid_t child) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    CHECK(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void signal_handler(int signo) { (void)signo; ++signals; }
static void delayed_frame(int fallback) {
    reset();
    no_fd = fallback;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        usleep(20000);
        _exit(write(channel[1], "F", 1) == 1 ? 0 : 1);
    }
    double start = milliseconds();
    CHECK(receiveFrameTimeout(0, 60) == 1 && callbacks == 1 && nonblock == 0);
    CHECK(milliseconds() - start >= 55);
    wait_child(child);
}

int main(void) {
    alarm(10);
    CHECK(pipe(channel) == 0);
    CHECK(fcntl(channel[0], F_SETFL, O_NONBLOCK) == 0);

    reset();
    CHECK(receiveFrameTimeout(0, -1) == -1 && errno == EINVAL && reads == 0);
    CHECK(receiveFrameTimeout(7, 10) == -1 && errno == ENODEV && reads == 0);
    setFrameReceiveCallback(NULL);
    CHECK(receiveFrameTimeout(0, 10) == -1 && errno == EINVAL && reads == 0);
    puts("PASS: invalid input does not touch capture");

    reset();
    queue("FF");
    double start = milliseconds();
    CHECK(receiveFrameTimeout(0, 40) == 2 && callbacks == 2);
    CHECK(milliseconds() - start >= 35);
    CHECK(nonblock == 0);
    puts("PASS: multiple queued frames processed, then wait until window ends");

    reset();
    start = milliseconds();
    CHECK(receiveFrameTimeout(0, 40) == 0);
    double elapsed = milliseconds() - start;
    CHECK(elapsed >= 35 && elapsed < 1000 && callbacks == 0 && nonblock == 0);
    CHECK(reads <= 5);
    printf("PASS: idle deadline, no busy loop (%.1f ms)\n", elapsed);

    reset();
    queue("FF");
    CHECK(receiveFrameTimeout(0, 0) == 0 && reads == 0 && callbacks == 0);
    CHECK(receiveFrameTimeout(0, 40) == 2 && callbacks == 2);
    puts("PASS: zero duration does not consume buffered frames");

    delayed_frame(0);
    delayed_frame(1);
    puts("PASS: delayed arrival with and without a selectable fd");

    reset();
    queue("SSF");
    CHECK(receiveFrameTimeout(0, 40) == 1 && callbacks == 1 && reads >= 3);
    puts("PASS: incomplete frames skipped before a valid frame");

    reset();
    queue("SSSS");
    start = milliseconds();
    CHECK(receiveFrameTimeout(0, 40) == 0);
    CHECK(milliseconds() - start < 1000 && callbacks == 0 && nonblock == 0);
    puts("PASS: incomplete frames do not prevent timeout");

    reset();
    queue("F");
    callback_fails = 1;
    CHECK(receiveFrameTimeout(0, 50) == -1 && errno == EIO && nonblock == 0);
    reset();
    force_capture_error = 1;
    CHECK(receiveFrameTimeout(0, 50) == -1 && errno == EIO && nonblock == 0);
    reset();
    queue("B");
    CHECK(receiveFrameTimeout(0, 50) == -1 && errno == EPIPE && nonblock == 0);
    puts("PASS: callback/capture failures restore blocking mode");

    reset();
    nonblock = 1;
    queue("F");
    CHECK(receiveFrameTimeout(0, 40) == 1 && nonblock == 1);
    CHECK(receiveFrameTimeout(0, 0) == 0 && nonblock == 1);
    puts("PASS: preexisting nonblocking mode preserved");

    reset();
    mode_failure = 1;
    CHECK(receiveFrameTimeout(0, 10) == -1 && errno == EIO && reads == 0);
    reset();
    queue("F");
    mode_failure = 2;
    CHECK(receiveFrameTimeout(0, 40) == -1 && errno == EIO && callbacks == 1);
    puts("PASS: mode change/restoration failures reported");

    reset();
    queue("FB");
    CHECK(receiveFrameTimeout(0, 40) == -1 && errno == EPIPE && callbacks == 1);
    CHECK(nonblock == 0);
    puts("PASS: capture failure after a frame still returns an error");

    reset();
    continuous_event = 'F';
    start = milliseconds();
    int processed = receiveFrameTimeout(0, 40);
    elapsed = milliseconds() - start;
    CHECK(processed == callbacks && processed > 1 && elapsed >= 35 && elapsed < 1000);
    CHECK(nonblock == 0);
    printf("PASS: continuous traffic cannot extend window (%.1f ms, %d frames)\n", elapsed, processed);

    reset();
    continuous_event = 'S';
    start = milliseconds();
    CHECK(receiveFrameTimeout(0, 40) == 0 && callbacks == 0);
    CHECK(milliseconds() - start < 1000 && nonblock == 0);
    puts("PASS: continuous incomplete frames cannot extend window");

    reset();
    queue("FF");
    slow_callback = 1;
    start = milliseconds();
    CHECK(receiveFrameTimeout(0, 20) == 1 && callbacks == 1 && nonblock == 0);
    CHECK(milliseconds() - start >= 55);
    puts("PASS: slow callback completes, then no further frames are processed");

    reset();
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    pid_t parent = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        for (int i = 0; i < 10; ++i) {
            usleep(5000);
            if (kill(parent, SIGUSR1) == -1) _exit(1);
        }
        _exit(0);
    }
    start = milliseconds();
    CHECK(receiveFrameTimeout(0, 40) == 0);
    elapsed = milliseconds() - start;
    CHECK(elapsed >= 35 && elapsed < 1000 && nonblock == 0);
    wait_child(child);
    CHECK(signals > 0);
    printf("PASS: interrupted waits retain deadline (%.1f ms)\n", elapsed);

    close(channel[0]);
    close(channel[1]);
    alarm(0);
    puts("All timed receive checks passed. No network traffic.");
    return 0;
}
