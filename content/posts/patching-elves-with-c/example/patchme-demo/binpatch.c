#include <stdio.h> // for declaration of puts

#define SECTION(x) __attribute__((section(x)))

SECTION(".patch.data.string1")
const char hello_binary_patching[] = "Hello, binary patching!";

SECTION(".patch.data.string2")
const char hello_linkerscript[] = "Hello, linkerscript magic!";

SECTION(".patch.code.i_do_something")
void i_do_something() {
  puts(hello_binary_patching);
  puts(hello_linkerscript);
}
