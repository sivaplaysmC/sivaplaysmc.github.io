CFLAGS=-fPIE

.PHONY: apply_patch
apply_patch: patchme binpatch.bin
	cp patchme patchme.orig
	dd if=binpatch.bin of=patchme \
		bs=1 seek=$$((0x1139)) \
		conv=notrunc,nocreat status=progress

patchme: patchme.c

binpatch.o: binpatch.c

binpatch.elf: binpatch.o binpatch.ld
	ld --no-warn-rwx-segments -pie -T binpatch.ld -o binpatch.elf binpatch.o

binpatch.bin: binpatch.elf
	objcopy --only-section '.patch' -O binary  binpatch.elf binpatch.bin

clean:
	rm -f binpatch.bin binpatch.elf binpatch.o patchme patchme.orig
