BIN=pei
INST_DIR=/usr/local/bin
CFLAGS= -pedantic-errors \
	-Wall \
	-Werror \
	-std=c11 \
	-I "include"

src2obj = $(subst .c,.o,$(1))
SRC=$(wildcard src/*.c src/operations/*.c src/pe/*.c src/utils/*.c)
OBJ=$(call src2obj,$(SRC))

all: CFLAGS += -O2
all: compile

debug: CFLAGS += -ggdb
debug: compile

compile: $(OBJ)
	$(CC) $(OBJ) -o $(BIN)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

install:
	cp $(BIN) $(INST_DIR)/$(BIN)

uninstall:
	rm $(INST_DIR)/$(BIN)
