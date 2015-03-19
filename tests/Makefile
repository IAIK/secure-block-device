Q=@
VGRUN = valgrind --tool=memcheck
VGPROF = valgrind --tool=callgrind --dump-instr=yes --cacheuse=yes

LDFLAGS += -lcppunit -ggdb $(EXTRA_LDFLAGS)
CFLAGS  += -Wall -ggdb -std=gnu++11 $(EXTRA_CFLAGS)
CXXFLAGS += -Wall -ggdb -std=gnu++11 $(EXTRA_CXXFLAGS)
CPPFLAGS += -std=gnu++11 -I../src/crypto/ -I../src/ -I../../merkle-tree/src

TST_DEP_FILE = .depend
TST_CXX_SRC = AesSivTest.cpp SbdiCtrTest.cpp SbdiCacheTest.cpp SbdiTestRunner.cpp SbdiBlockLayerTest.cpp SbdiTest.cpp
TST_CXX_OBJS = $(TST_CXX_SRC:%.cpp=%.o)
TST_SRC = $(TST_CXX_SRC)
TST_OBJS = $(TST_CXX_OBJS)
TST_LIB =  -Wl,--start-group ../../merkle-tree/src/libMerkleTree.a ../src/crypto/libSbdiCrypto.a ../src/libSecureBlock.a -Wl,--end-group 
TST_BIN = secure-block-test

all: dep $(TST_BIN)

coverage: LDFLAGS +=-ggdb -coverage
coverage: CFLAGS +=-ggdb -fprofile-arcs -ftest-coverage
coverage: dep $(TST_BIN)

test: $(TST_BIN)
	$(Q)$(VGRUN) ./$(TST_BIN)
	
prof: $(TST_BIN)
	$(Q)$(VGPROF) ./$(TST_BIN)

.PHONY: clean
clean:
	$(Q)rm -Rf $(TST_BIN) $(TST_OBJS) html latex .depend

$(TST_BIN): $(TST_OBJS) $(TST_LIB)
	$(Q)$(CXX) $(CFLAGS) $(CPPFLAGS) -o $(TST_BIN) $(TST_OBJS) $(TST_LIB) $(LDFLAGS)

$(TST_LIB):
	$(Q)$(MAKE) -C ../src/ debug

dep: $(TST_SRC)
	$(Q)$(CXX) $(CPPFLAGS) -MM $(TST_SRC) > $(TST_DEP_FILE)

-include $(TST_DEP_FILE)
