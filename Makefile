CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Isrc
LDLIBS ?= -lpcap
TEST_DIR := $(if $(wildcard test/*.c),test,src/test)
DEVICE ?= enp3s0

PROGRAMS := tmp/list_devices tmp/test_device \
            tmp/lab-netstack-test-device-mac \
            tmp/lab-netstack-test-packetio-args \
            tmp/lab-netstack-test-packetio-receive \
            tmp/lab-netstack-send-demo tmp/lab-netstack-receive-demo

.PHONY: all check check-device clean
all: $(PROGRAMS)

tmp:
	mkdir -p $@

tmp/list_devices: $(TEST_DIR)/list_devices.c | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

tmp/test_device: src/device.c $(TEST_DIR)/test_device.c src/device.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-device-mac: src/device.c $(TEST_DIR)/test_device_mac.c src/device.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-packetio-args: src/packetio.c $(TEST_DIR)/test_packetio_args.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

tmp/lab-netstack-test-packetio-receive: src/packetio.c $(TEST_DIR)/test_packetio_receive.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

tmp/lab-netstack-send-demo: src/device.c src/packetio.c $(TEST_DIR)/send_demo.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-receive-demo: src/device.c src/packetio.c $(TEST_DIR)/receive_demo.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

check: tmp/lab-netstack-test-packetio-args tmp/lab-netstack-test-packetio-receive
	./tmp/lab-netstack-test-packetio-args
	./tmp/lab-netstack-test-packetio-receive

check-device: tmp/test_device tmp/lab-netstack-test-device-mac
	sudo ./tmp/test_device "$(DEVICE)"
	sudo ./tmp/lab-netstack-test-device-mac "$(DEVICE)"

clean:
	rm -f $(PROGRAMS)
