SECTIONS
{
    . = 0xdeadbeefcafebabe;
    .patch ALIGN(1) : SUBALIGN(1)
    {
        KEEP (*(.patch))
    }
}

