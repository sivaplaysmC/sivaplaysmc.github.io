#define SECTION(x) __attribute__((section(x)))

// this section should be placed at address 0xdeadbeefcafebabe
SECTION(".patch")
int foo(void) {
    return 42;
};
