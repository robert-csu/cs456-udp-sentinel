CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2 -g -pthread
CFLAGS += -MMD -MP

SRC = src
BUILD = build
BIN = bin
TESTDIR = tests
SCRIPTS = scripts

PROGS = sentinel monitor client
PROG_BINS = $(addprefix $(BIN)/, $(PROGS))

TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS = $(patsubst $(TESTDIR)/%.c, $(BIN)/tests/%, $(TEST_SRCS))
SCRIPT_TESTS = $(wildcard $(SCRIPTS)/test_*.sh)
COMMON_OBJS = $(BUILD)/state.o

.PHONY: all tests test clean distclean

all: $(PROG_BINS)

$(BIN)/sentinel: $(BUILD)/sentinel.o $(COMMON_OBJS) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN)/%: $(BUILD)/%.o | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

tests: $(TEST_BINS)

$(BIN)/tests/%: $(TESTDIR)/%.c $(COMMON_OBJS) | $(BIN)/tests
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $< $(COMMON_OBJS)

test: all tests
	@set -e; \
	for t in $(TEST_BINS); do echo "== $$t"; ./$$t; done; \
	for s in $(SCRIPT_TESTS); do echo "== $$s"; bash $$s; done; \
	echo "All tests passed"

$(BUILD) $(BIN) $(BIN)/tests:
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

distclean: clean
	find logs -type f ! -name .gitkeep -delete

-include $(wildcard $(BUILD)/*.d) $(wildcard $(BIN)/tests/*.d) $(wildcard $(BIN)/tests/*.d)