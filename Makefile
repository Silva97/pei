BIN=pei
INST_DIR=/usr/local/bin
CFLAGS= -pedantic-errors \
	-Wall \
	-Werror \
	-std=c11 \
	-I "include"

src2obj = $(subst .c,.o,$(1))
SRC=$(wildcard src/operations/*.c src/pe/*.c src/utils/*.c)
OBJ=$(call src2obj,$(SRC))

all: CFLAGS += -O2
all: compile

debug: CFLAGS += -ggdb
debug: compile

compile: $(OBJ) compile_main
	$(CC) $(OBJ) src/main.o -o $(BIN)

compile_main:
	$(CC) $(CFLAGS) -c src/main.c -o src/main.o

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) src/main.o
	rm -rf obj/

install:
	cp $(BIN) $(INST_DIR)/$(BIN)
	cp autocomplete.sh /etc/bash_completion.d/pei

uninstall:
	rm $(INST_DIR)/$(BIN)
	rm /etc/bash_completion.d/pei

# This rule expects $(CC) is the MinGW-w64 compiler. Example:
#   CC=x86_64-w64-mingw32-gcc make compile_test_pe
compile_test_pe:
	$(CC) -m64 tests/utils/test.c -o tests/utils/test.exe

test: CFLAGS += -I tests/utils/include -Wno-unused-variable
test: $(OBJ)
	@mkdir -p obj
	@$(CC) $(CFLAGS) -c -DANSI_COLORS tests/test_$(name).c -o obj/test_$(name).o
	@$(CC) $(OBJ) obj/test_$(name).o -o metric_test
	@./metric_test
