all:
	$(CC) src/main.c src/pe/*.c -o pe -I include
