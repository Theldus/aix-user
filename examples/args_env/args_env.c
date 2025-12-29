#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, const char **argv, const char **envp) {
  char *shell;
  const char **p;

  for (int i = 0; i < argc; i++)
    printf("argv[%d] = (%s)\n", i, argv[i]);

  shell = getenv("SHELL");
  if (!shell) {
    printf("SHELL env var not found!\n");
    return 100;
  }

  for (p = envp; *p; p++) {
    if (strstr(*p, "SHELL")) {
      printf("Shell (through env var loop): (%s)\n", *p);
      break;
    }
  }

  if (!strstr(shell, "bash")) {
    printf("Shell is not bash!!, shell: (%s)\n", shell);
    return 50;
  }
  else
    printf("SHELL is bash!\n");

  return 42; /* 0 is soo generic, lets use smth better =). */
}

