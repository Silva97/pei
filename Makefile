all:
	$(CC) src/*.c src/operations/*.c src/pe/*.c src/utils/*.c -std=c11 -o pei -I include
