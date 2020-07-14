CFLAGS += -Werror -Wall
all: pam_flight.so pam_flight_user_map.so

clean:
	$(RM) pam_flight.so pam_flight_user_map.so *.o

pam_flight_user_map.so: src/pam_flight_user_map.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $<

pam_flight.so: src/pam_flight.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

install: pam_flight.so pam_flight_user_map.so
	install -m 755 pam_flight.so $(PREFIX)/usr/lib/security/
	install -m 755 pam_flight_user_map.so $(PREFIX)/usr/lib/security/
	install -m 644 src/flight_user_map.conf $(PREFIX)/etc/security/
