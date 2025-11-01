#include <stdio.h>
#include <unistd.h>

int main() {
  printf("Beginning ...\n");
  int pid = fork();
  printf("Fork returned %d\n", pid);
}

