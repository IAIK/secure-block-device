Q = @
CFLAGS  +=-Wall -Werror -pedantic -std=gnu99
CPPFLAGS = -I../

DEPENDFILE = .depend
LIB_SRC = rijndael-alg-fst.c aes.c ocb.c siv.c sbdi_nocrypto.c sbdi_ocb.c sbdi_siv.c
SRC = $(LIB_SRC)
LIB_OBJS = $(LIB_SRC:%.c=%.o)
OBJS = $(LIB_OBJS)
LIB = libSbdiCrypto.a
EXT_LIB =

NWD_PERF_SRC  = nwd-perf.c nwd-stopwatch.c
NWD_PERF_OBJS = $(NWD_PERF_SRC:%.c=%.o)
NWD_PERF_APP  = nwd-crypto-perf

OBJS += $(NWD_PERF_OBJS)

CFLAGS  += $(CPPFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += $(EXT_LIB) $(EXTRA_LDFLAGS)

all: debug

debug: LDFLAGS +=-ggdb
debug: CFLAGS +=-ggdb
debug: dep $(LIB) $(NWD_PERF_APP)

coverage: LDFLAGS +=-ggdb -coverage
coverage: CFLAGS +=-ggdb -fprofile-arcs -ftest-coverage
coverage: dep $(LIB) $(NWD_PERF_APP)

#silent: CFLAGS +=-ggdb -pg
silent: CFLAGS +=-ggdb
silent: clean dep $(LIB) $(NWD_PERF_APP)

release: CFLAGS +=-O3 -fgnu89-inline
release: clean dep $(LIB) $(NWD_PERF_APP)

.PHONY: clean doc
clean:
	$(Q)rm -Rf $(NWD_PERF_APP) $(OBJS) $(LIB) html latex .depend *.gcov *.gcno *.gcda

doc:
	$(Q)doxygen

$(LIB): $(LIB_OBJS)
	$(Q)$(AR) crvs $(LIB) $(LIB_OBJS)

dep: $(SRC)
	$(Q)$(CC) $(CPPFLAGS) -MM $(SRC) > $(DEPENDFILE)

# Normal world performance test app
$(NWD_PERF_OBJS): CFLAGS  += -I. -I.. -I../../../merkle-tree/src
$(NWD_PERF_APP):  LDFLAGS +=
$(NWD_PERF_APP):  LIBS    += -L ../../../merkle-tree/src -L. -lMerkleTree -lSbdiCrypto -lrt -lm

$(NWD_PERF_APP): $(NWD_PERF_OBJS) $(LIB)
	$(Q)$(CC) -o$@ $(LDFLAGS) $(NWD_PERF_OBJS) $(LIBS)


-include $(DEPENDFILE)
