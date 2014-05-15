Q=@
VGRUN = valgrind --tool=memcheck 

LDFLAGS += -lcppunit -ggdb
CFLAGS  += -Wall -ggdb
CXXFLAGS += -Wall -ggdb
CPPFLAGS += -I../src/ -I..src/crypto/

TST_DEP_FILE = .depend
TST_CXX_SRC = AesSivTest.cpp SbdiCtrTest.cpp SbdiTestRunner.cpp
TST_CXX_OBJS = $(TST_CXX_SRC:%.cpp=%.o)
TST_SRC = $(TST_CXX_SRC)
TST_OBJS = $(TST_CXX_OBJS)
TST_LIB = ../src/crypto/libSbdiCrypto.a ../src/libSecureBlock.a
TST_BIN = secure-block-test

all: dep $(TST_BIN) 

test: $(TST_BIN)
	$(Q)$(VGRUN) ./$(TST_BIN)

.PHONY: clean
clean:
	$(Q)rm -Rf $(TST_BIN) $(TST_OBJS) html latex .depend

$(TST_BIN) : $(TST_OBJS) $(TST_LIB)
	$(Q)$(CXX) $(CFLAGS) $(CPPFLAGS) -o $(TST_BIN) $(TST_OBJS) $(TST_LIB) $(LDFLAGS)

$(TST_LIB):
	$(Q)$(MAKE) -C ../src/ all

dep: $(TST_SRC)
	$(Q)$(CXX) $(CPPFLAGS) -MM $(TST_SRC) > $(TST_DEP_FILE)

-include $(TST_DEP_FILE)
