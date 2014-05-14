Q = @
CFLAGS  +=-Wall -Werror -pedantic -std=gnu99
	
DEPENDFILE = .depend
LIB_SRC = rijndael-alg-fst.c aes.c aes_cmac_128.c siv.c
PRG_SRC = crypto_test.c
SRC = $(LIB_SRC) $(PRG_SRC)
LIB_OBJS = $(LIB_SRC:%.c=%.o)
PRG_OBJS = $(PRG_SRC:%.c=%.o)
OBJS = $(LIB_OBJS) $(PRG_OBJS)
LIB = libSbdiCrypto.a
EXT_INC = 
EXT_LIB = 
BIN = sbdi-crypto-test

CFLAGS  += $(EXT_INC)
LDFLAGS += $(EXT_LIB)

all: silent

debug: LDFLAGS +=-ggdb
debug: CFLAGS +=-ggdb
debug: dep $(BIN)

coverage: LDFLAGS +=-ggdb -coverage
coverage: CFLAGS +=-ggdb -fprofile-arcs -ftest-coverage
coverage: dep $(BIN)

#silent: CFLAGS +=-ggdb -pg
silent: CFLAGS +=-ggdb
silent: clean dep $(BIN)

release: CFLAGS +=-O3 -fgnu89-inline
release: clean dep $(BIN) FORCE
	
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

 
