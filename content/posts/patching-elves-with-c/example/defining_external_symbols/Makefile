CFLAGS=-O0 -fpie

export.zip: main
	zip export.zip default.ld  linkerscript.ld  main  main.c  main.o  Makefile

main: main.o linkerscript.ld default.ld
	ld -T linkerscript.ld -o main main.o

default.ld:
	ld --verbose | sed -n '/^====/,/^====/p' | sed '/^=*$/d' > default.ld

main.o: main.c
