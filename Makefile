all:
	$(CC) src/main.c src/pe/*.c -std=c11 -o pei -I include
