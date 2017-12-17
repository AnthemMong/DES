a.out : test.o des.o table.o
	gcc test.o des.o table.o

test.o : des.h des.c test.c
	gcc -c test.c des.c
des.o : des.c des.h
	gcc -c des.c
array.o : des.h array.c
	gcc -c table.c
clean : 
	rm test.o des.o