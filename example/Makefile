all:
	gcc -c -Wall -Wextra -fpic library.c
	gcc -shared -o libhelloworld.so library.o

32:
	gcc -c -Wall -Wextra -fpic -m32 library.c -o library32.o
	gcc -shared -m32 -o libhelloworld32.so library32.o

clean:
	rm -f library.o library32.o
