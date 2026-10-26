CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2 -g
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

.PHONY: all tests test clean distclean

all: $(PROG_BINS)

$(BIN)/%: $(BUILD)/%.o | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

tests: $(TEST_BINS)

$(BIN)/tests/%: $(TESTDIR)/%.c | $(BIN)/tests
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $<

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

-include $(wildcard $(BUILD)/*.d) $(wildcard $(BIN)/tests/*.d)