

all: main.c
	gcc main.c -o elf/main
	gcc main.c -no-pie -o main-exec

clean:
	rm -f elf/main
	rm -f elf/main-exec
