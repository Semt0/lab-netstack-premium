CC ?= gcc
CPPFLAGS += -Isrc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -Werror
CFLAGS += -pthread
LDLIBS ?= -lpcap

LIB_SOURCES := $(filter-out src/main.c,$(wildcard src/*.c))
HEADERS := $(wildcard src/*.h)

MAIN_TARGET := tmp/lab-main
CP3_TARGET := tmp/send-ipv4-demo
CP4_TARGET := tmp/cp4-router
CP6_TARGET := tmp/cp6-lpm
TARGETS := $(MAIN_TARGET) $(CP3_TARGET) $(CP4_TARGET) $(CP6_TARGET)

.PHONY: all main cp3 cp4 cp5 cp6 clean
all: main

main: $(MAIN_TARGET)

cp3: $(CP3_TARGET)

cp4: $(CP4_TARGET)

cp5: $(CP4_TARGET)

cp6: $(CP6_TARGET)

$(MAIN_TARGET): src/main.c $(LIB_SOURCES) $(HEADERS) Makefile | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(CP3_TARGET): test/cp3/send_ipv4_demo.c $(LIB_SOURCES) $(HEADERS) Makefile | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(CP4_TARGET): test/cp4/router.c $(LIB_SOURCES) $(HEADERS) Makefile | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(CP6_TARGET): test/cp6/lpm.c $(LIB_SOURCES) $(HEADERS) Makefile | tmp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

tmp:
	mkdir -p $@

clean:
	rm -f $(TARGETS)
