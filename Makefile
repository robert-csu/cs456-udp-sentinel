CC = gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2 -g -pthread
CFLAGS += -MMD -MP

BUILD = build
BIN = bin
TESTDIR = tests
SCRIPTS = scripts
CONFIG = config

PROGS = sentinel monitor client
PROG_BINS = $(addprefix $(BIN)/, $(PROGS))
PROG_OBJS = $(addprefix $(BUILD)/, $(addsuffix .o, $(PROGS)))

TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS = $(patsubst $(TESTDIR)/%.c,$(BIN)/tests/%,$(TEST_SRCS))
SCRIPT_TESTS = $(wildcard $(SCRIPTS)/test_*.sh)

BLACKLIST = $(CONFIG)/blacklist.txt

.PHONY: all setup tests test run-monitor run-sentinel run-sentinel-crash run-client clean distclean
.SECONDARY: $(PROG_OBJS)

all: $(PROG_BINS)

# Link programs
$(BIN)/%: $(BUILD)/%.o | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# Compile source files from project root
$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

# Create config/blacklist.txt if it doesn't exist
setup: $(BLACKLIST)

$(BLACKLIST): | $(CONFIG)
	touch $@

# Build C tests
tests: $(TEST_BINS)

$(BIN)/tests/%: $(TESTDIR)/%.c | $(BIN)/tests
	$(CC) $(CFLAGS) -I. -o $@ $<

# Run all tests
test: all tests
	@set -e; \
	for t in $(TEST_BINS); do echo "== $$t"; ./$$t; done; \
	for s in $(SCRIPT_TESTS); do echo "== $$s"; bash $$s; done; \
	echo "All tests passed"

# Convenience run commands
run-monitor: all
	./$(BIN)/monitor

run-sentinel: all setup
	./$(BIN)/sentinel --no-crash

run-sentinel-crash: all setup
	./$(BIN)/sentinel

run-client: all
	./$(BIN)/client

$(BUILD) $(BIN) $(BIN)/tests $(CONFIG):
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

distclean: clean
	rm -f monitor.log beat.bin
	rm -rf __pycache__
	@if [ -d logs ]; then find logs -type f ! -name .gitkeep -delete; fi

-include $(wildcard $(BUILD)/*.d) $(wildcard $(BIN)/tests/*.d)