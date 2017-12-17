ARG = test.o des.o table.o

a.out : $(ARG)
	gcc $(ARG)

test.o : des.h des.c test.c
	gcc -c test.c des.c
des.o : des.c des.h
	gcc -c des.c
table.o : des.h table.c
	gcc -c table.c
clean : 
	rm $(ARG)
