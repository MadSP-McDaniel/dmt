includes=.
sources=mt.cc mt_support.cc dmt.cc trace.cc cache.cc common.cc disk.cc
libs=-lbdus -lm -lgcrypt -pthread
CC=g++

all: codeql

codeql: $(sources) main.cc test.cc
	$(CC) -DFIXED_ARITY=2 -O2 -Wall main.cc -I$(includes) $(sources) $(libs) -o dmt
	$(CC) -DFIXED_ARITY=2 -O2 -Wall test.cc -I$(includes) $(sources) $(libs) -o dmt_test

# very verbose
debug0: $(sources) main.cc test.cc
	$(CC) $(CXXFLAGS) -O0 -g -Wall -D__DEBUG main.cc -I$(includes) $(sources) $(libs) -o dmt
	$(CC) $(CXXFLAGS) -O0 -g -Wall -D__DEBUG test.cc -I$(includes) $(sources) $(libs) -o dmt_test

# less verbose
debug1: $(sources) main.cc test.cc
	$(CC) $(CXXFLAGS) -O0 -g -Wall main.cc -I$(includes) $(sources) $(libs) -o dmt
	$(CC) $(CXXFLAGS) -O0 -g -Wall test.cc -I$(includes) $(sources) $(libs) -o dmt_test

# only logs errors
dmt: $(sources) main.cc test.cc
	$(CC) $(CXXFLAGS) -O2 -Wall main.cc -I$(includes) $(sources) $(libs) -o dmt
	$(CC) $(CXXFLAGS) -O2 -Wall test.cc -I$(includes) $(sources) $(libs) -o dmt_test

clean:
	rm -rf dmt dmt_test *.o
