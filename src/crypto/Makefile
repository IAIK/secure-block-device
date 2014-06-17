Q = @
CFLAGS  +=-Wall -Werror -pedantic -std=gnu99
CPPFLAGS = -I../
	
DEPENDFILE = .depend
LIB_SRC = rijndael-alg-fst.c aes.c aes_cmac_128.c siv.c sbdi_siv.c sbdi_nocrypto.c
SRC = $(LIB_SRC)
LIB_OBJS = $(LIB_SRC:%.c=%.o)
OBJS = $(LIB_OBJS)
LIB = libSbdiCrypto.a
EXT_LIB = 

CFLAGS  += $(CPPFLAGS)
LDFLAGS += $(EXT_LIB)

all: debug

debug: LDFLAGS +=-ggdb
debug: CFLAGS +=-ggdb
debug: dep $(LIB)

coverage: LDFLAGS +=-ggdb -coverage
coverage: CFLAGS +=-ggdb -fprofile-arcs -ftest-coverage
coverage: dep $(LIB)

#silent: CFLAGS +=-ggdb -pg
silent: CFLAGS +=-ggdb
silent: clean dep $(LIB)

release: CFLAGS +=-O3 -fgnu89-inline
release: clean dep $(LIB) FORCE
	
.PHONY: clean doc
clean:
	$(Q)rm -Rf $(OBJS) $(LIB) html latex .depend *.gcov *.gcno *.gcda

doc:
	$(Q)doxygen

$(LIB): $(LIB_OBJS)
	$(Q)$(AR) crvs $(LIB) $(LIB_OBJS)

dep: $(SRC)
	$(Q)$(CC) $(CPPFLAGS) -MM $(SRC) > $(DEPENDFILE)

-include $(DEPENDFILE)

 
