CFLAGS += -Werror -Wall
all: test pam-flight.so

clean:
	$(RM) test pam-flight.so *.o

pam-flight.so: src/pam-flight.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

test: src/test.c
	$(CC) $(CFLAGS) -o $@ $< -lpam -lpam_misc

install: pam-flight.so
	install -m 755 pam-flight.so $(PREFIX)/lib64/security
