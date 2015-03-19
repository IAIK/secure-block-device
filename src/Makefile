Q = @
CFLAGS  +=-Wall -Werror -pedantic -std=gnu99

DEPENDFILE = .depend
LIB_SRC = sbdi.c sbdi_hdr.c sbdi_block.c sbdi_ctr_128b.c sbdi_cache.c sbdi_buffer.c sbdi_pio.c sbdi_debug.c
PRG_SRC = sbdi_test.c
SRC = $(LIB_SRC) $(PRG_SRC)
LIB_OBJS = $(LIB_SRC:%.c=%.o)
PRG_OBJS = $(PRG_SRC:%.c=%.o)
OBJS = $(LIB_OBJS) $(PRG_OBJS)
LIB = libSecureBlock.a
EXT_INC = -I. -I../../merkle-tree/src -I./crypto
EXT_LIB = -L../../merkle-tree/src -L./crypto -lMerkleTree -lSbdiCrypto
BIN = sbdi-test

CFLAGS  += $(EXT_INC) $(EXTRA_CFLAGS)
LDFLAGS += $(EXT_LIB) $(EXTRA_LDFLAGS)

all: debug

debug: LDFLAGS +=-ggdb
debug: CFLAGS +=-ggdb -DSBDI_DEBUG
debug: dep $(BIN)

coverage: LDFLAGS +=-ggdb -coverage
coverage: CFLAGS +=-ggdb -fprofile-arcs -ftest-coverage
coverage: dep $(BIN)

#silent: CFLAGS +=-ggdb -pg
silent: CFLAGS +=-ggdb
silent: clean dep $(BIN)

release: CFLAGS +=-O3 -fgnu89-inline
release: clean dep $(BIN)

.PHONY: clean doc
clean:
	$(Q)rm -Rf $(BIN) $(OBJS) $(LIB) html latex .depend *.gcov *.gcno *.gcda

doc:
	$(Q)doxygen

$(BIN) : $(PRG_OBJS) $(LIB)
	$(Q)$(CC) $(CFLAGS) -o $(BIN) $(PRG_OBJS) $(LIB) $(LDFLAGS)

$(LIB): $(LIB_OBJS)
	$(Q)$(AR) crvs $(LIB) $(LIB_OBJS)

dep: $(SRC)
	$(Q)$(CC) $(EXT_INC) -MM $(SRC) > $(DEPENDFILE)

-include $(DEPENDFILE)
