#include <stdio.h>

int globalVariable = 5;

short anotherFunc(char a);

int main()
{
    short sum = 0;

    printf("Hello world! %d\n", globalVariable);
    sum = anotherFunc(globalVariable);
    printf("Result: %d\n", sum);
    if ( sum > 3 )
    {
        printf("This is a miracle!\n");
    }
    else
    {
        printf("Sum is too small\n");
    }
    return 0;
}

short anotherFunc(char a)
{
    int b = 0;
    int c = 1;
    int result = 0;

    result = a + b + c;
    result = a - c;
    result++;
    result--;
    result = 1000 / 2;
    result = c * 40;
    a = 16;
    b = 5;
    result = a > 2;
    result = a > b;
    result = a < 2;
    result = a < b;

    a = 0;
    b = 0;

    for ( int i = 0; i < 32; i++)
    {
        if ( i % 2 == 0)
        {
            a += i;
        }
        else
        {
            b += i;
        }
    }

    return a + b;
}
