CFLAGS += -Werror -Wall
all: test pam_flight.so

clean:
	$(RM) test pam_flight.so *.o

pam_flight.so: src/pam_flight.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

test: src/test.c
	$(CC) $(CFLAGS) -o $@ $< -lpam -lpam_misc

install: pam_flight.so
	install -m 755 pam_flight.so $(PREFIX)/usr/lib/security/
