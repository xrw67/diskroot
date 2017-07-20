all:
	gcc -g -o diskroot $(wildcard *.c)


clean:
	rm -rf *.o diskroot

debug:
	gdb ./diskroot
