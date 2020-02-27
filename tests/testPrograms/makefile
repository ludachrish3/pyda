

all: main.c
	gcc main.c -o elf/main -lpthread
	gcc main.c -no-pie -o elf/main-exec -lpthread

clean:
	rm -f elf/main
	rm -f elf/main-exec
