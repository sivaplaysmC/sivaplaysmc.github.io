patch_at = 0x01139;
patch_size = 511;

puts = 0x1030;

SECTIONS
{
    /*
     * force linker to put things where our code cave will be.
     * We will use `objcopy` to extract this `.patch` section,
     * and patch it onto the target with `dd`.
     */
    . = patch_at;
    .patch ALIGN(1) : SUBALIGN(1)
    {
        /* Place executable code before any embedded data.
         *
         * Emitting code first guarantees that the instruction pointer never
         * lands in non-executable payload data (e.g. embedded strings),
         * which would otherwise result in undefined behavior or a crash.
         */
        KEEP(*(.patch.code.*))

        KEEP(*(.patch.data.*))
    }
    ASSERT(SIZEOF(.patch) <= patch_size, "patch is too big")
}

