all:
	$(CC) src/*.c src/pe/*.c src/utils/*.c -std=c11 -o pei -I include
