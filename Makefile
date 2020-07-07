CFLAGS += -Werror -Wall
all: test flight-pam.so

clean:
	$(RM) test flight-pam.so *.o

flight-pam.so: src/flight-pam.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

test: src/test.c
	$(CC) $(CFLAGS) -o $@ $< -lpam -lpam_misc

install: flight-pam.so
    install -m 755 flight-pam.so $(PREFIX)/lib64/security
