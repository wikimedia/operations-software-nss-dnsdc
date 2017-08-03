# This file is part of dnsdc.
#
# dnsdc is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# dnsdc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dnsdc.  If not, see <http://www.gnu.org/licenses/>.


CFLAGS ?= -O2 -Wall

PQCFLAGS = -fPIC

all: cli libnss_dnsdc.so.2

nss: libnss_dnsdc.so.2

nss-dnsdc.o:
	$(CC) -o $@ $(LDFLAGS) -DLOGGING=1 -shared -Wl,-soname,$@ $^

cli:
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) -DLOGGING=1 nss-dnsdc.c cli.c

libnss_dnsdc.so.2: nss-dnsdc.o
	$(CC) -o $@ $(LDFLAGS) -DLOGGING=1 -shared -Wl,-soname,$@ $^

clean:
	rm -f nss-dnsdc.o libnss_dnsdc.so.2 dnstest cli

#install: libnss_dnsdc.so.2
#	install -m 0644 libnss_dnsdc.so.2 /lib/x86_64-linux-gnu/
#	/sbin/ldconfig -n /lib/x86_64-linux-gnu/ /usr/lib
