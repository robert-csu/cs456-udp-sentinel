# cs456-udp-sentinel

## Build and run

```sh
make              # build sentinel, monitor, client into bin/
make tests        # build the C unit tests in tests/ into bin/tests/
make test         # build everything, run the C unit tests, then scripts/test_*.sh
make clean        # remove build/ and bin/
make distclean    # clean, plus delete everything in logs/
```
