#include <stdio.h>

int globalVariable = 5;

short anotherFunc(char a);

int main()
{
    short sum = 0;

    printf("Hello world! %d\n", globalVariable);
    sum = anotherFunc(globalVariable);
    printf("Sum: %d\n", sum);
    return 0;
}

short anotherFunc(char a)
{
    char b = 0;
    char c = 1;

    return a + b + c;
}
