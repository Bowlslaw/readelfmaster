CC=gcc
all:
	$(CC) readelfmaster.c /opt/libelfmaster/src/libelfmaster.a -o readelfmaster
	$(CC) test.c -o test
clean:
	rm readelfmaster test
