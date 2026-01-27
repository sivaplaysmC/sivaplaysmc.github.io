CFLAGS=-O0 -fpie

export.zip: main
	zip export.zip linkerscript.ld  main  main.c  main.o  Makefile

main: main.o linkerscript.ld
	ld --no-warn-rwx-segments -T linkerscript.ld -o main main.o

main.o: main.c
