
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g -pthread
CFLAGS += -MMD -MP

SRC = src
BUILD = build
BIN = bin
TESTDIR = tests
SCRIPTS = scripts
CONFIG = config

BLACKLIST = $(CONFIG)/blacklist.txt

COMMON_OBJS = $(BUILD)/state.o $(BUILD)/checkpoint.o

PROG_BINS = $(BIN)/sentinel $(BIN)/monitor $(BIN)/client

TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS = $(patsubst $(TESTDIR)/%.c,$(BIN)/tests/%,$(TEST_SRCS))

SCRIPT_TESTS = $(wildcard $(SCRIPTS)/test_*.sh)

.PHONY: all setup tests test run-monitor run-sentinel \
        run-sentinel-crash run-client clean distclean

# Default build
all: $(PROG_BINS)

# Sentinel requires state and checkpoint modules
$(BIN)/sentinel: $(BUILD)/sentinel.o $(COMMON_OBJS) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

# Monitor
$(BIN)/monitor: $(BUILD)/monitor.o | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

# Client
$(BIN)/client: $(BUILD)/client.o | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

# Compile C files from src/
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -c -o $@ $<

# Compile tests with required modules
tests: $(TEST_BINS)

$(BIN)/tests/%: $(TESTDIR)/%.c $(COMMON_OBJS) | $(BIN)/tests
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $^

# Setup configuration directory and blacklist
setup: $(BLACKLIST)

$(BLACKLIST): | $(CONFIG)
	touch $@

# Run all C and shell tests
test: all tests
	@set -e; \
	for t in $(TEST_BINS); do \
		echo "Running $$t"; \
		./$$t; \
	done; \
	for s in $(SCRIPT_TESTS); do \
		echo "Running $$s"; \
		bash $$s; \
	done; \
	echo "All tests passed"

# Run monitor
run-monitor: all
	./$(BIN)/monitor

# Run Sentinel without random crashes
run-sentinel: all setup
	./$(BIN)/sentinel --no-crash

# Run Sentinel with random crashes
run-sentinel-crash: all setup
	./$(BIN)/sentinel

# Run client
run-client: all
	./$(BIN)/client

# Create directories
$(BUILD) $(BIN) $(BIN)/tests $(CONFIG):
	mkdir -p $@

# Remove compiled files
clean:
	rm -rf $(BUILD) $(BIN)

# Remove generated logs and temporary files
distclean: clean
	rm -f monitor.log beat.bin
	rm -rf __pycache__
	@if [ -d logs ]; then \
		find logs -type f ! -name .gitkeep -delete; \
	fi

# Track header dependencies
-include $(wildcard $(BUILD)/*.d)
-include $(wildcard $(BIN)/tests/*.d)
