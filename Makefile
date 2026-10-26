CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Isrc
LDLIBS ?= -lpcap
TEST_DIR := $(if $(wildcard test/*.c),test,src/test)
DEVICE ?= enp3s0

PROGRAMS := tmp/list_devices tmp/test_device \
            tmp/lab-netstack-test-device-mac \
            tmp/lab-netstack-test-device-handles \
            tmp/lab-netstack-test-packetio-args \
            tmp/lab-netstack-test-packetio-receive \
            tmp/lab-netstack-send-demo tmp/lab-netstack-receive-demo \
            tmp/lab-netstack-main tmp/lab2-send-ipv4 tmp/lab2-test-ipv4

.PHONY: all check check-device clean lab2 check-lab2
all: $(PROGRAMS)

lab2: tmp/lab-netstack-main tmp/lab2-send-ipv4

check-lab2: tmp/lab2-test-ipv4
	./tmp/lab2-test-ipv4

tmp:
	mkdir -p $@

tmp/list_devices: $(TEST_DIR)/list_devices.c | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

tmp/test_device: src/device.c $(TEST_DIR)/test_device.c src/device.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-device-mac: src/device.c $(TEST_DIR)/test_device_mac.c src/device.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-device-handles: src/device.c $(TEST_DIR)/test_device_handles.c src/device.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-packetio-args: src/packetio.c $(TEST_DIR)/test_packetio_args.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-test-packetio-receive: src/packetio.c $(TEST_DIR)/test_packetio_receive.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-send-demo: src/device.c src/packetio.c $(TEST_DIR)/send_demo.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-receive-demo: src/device.c src/packetio.c $(TEST_DIR)/receive_demo.c src/device.h src/packetio.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab-netstack-main: src/main.c src/device.c src/packetio.c src/ip.c src/smtarp.c src/smtroute.c src/device.h src/packetio.h src/ip.h src/smtarp.h src/smtroute.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab2-send-ipv4: test/send_ipv4_demo.c src/device.c src/packetio.c src/ip.c src/smtarp.c src/smtroute.c src/device.h src/packetio.h src/ip.h src/smtarp.h src/smtroute.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp/lab2-test-ipv4: src/ip.c test/test_ipv4.c src/ip.h src/device.h src/packetio.h src/smtarp.h src/smtroute.h | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

check: tmp/lab-netstack-test-packetio-args tmp/lab-netstack-test-packetio-receive tmp/lab-netstack-test-device-handles
	./tmp/lab-netstack-test-packetio-args
	./tmp/lab-netstack-test-packetio-receive
	./tmp/lab-netstack-test-device-handles

check-device: tmp/test_device tmp/lab-netstack-test-device-mac
	sudo ./tmp/test_device "$(DEVICE)"
	sudo ./tmp/lab-netstack-test-device-mac "$(DEVICE)"

clean:
	rm -f $(PROGRAMS)
