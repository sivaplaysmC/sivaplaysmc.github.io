// compile with: make patchme

#include <stdio.h>
#include <sys/cdefs.h>

volatile int i_do_nothing() {
  __asm__ volatile(".rept 500\n\t"
                   "nop\n\t"
                   ".endr\n\t");

  return 42;
}

int main(void) {
  puts("Hello! Go ahead and patch me!");
  volatile int ret = i_do_nothing();
  return ret;
}
