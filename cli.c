#include <stdio.h>
#include <unistd.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>

#include "nss-dnsdc.h"

#define BUFLEN 2048

void resolve(const char *hostname, int af, int maxaddrlen) {
	struct hostent host;
	char buf[BUFLEN];
	int errnop, h_errnop;
	enum nss_status res;
	struct in_addr **addr_list;
	int i;
   
	if (af == AF_INET) {
		printf("A ");
	} else if (af == AF_INET6) {
		printf("AAAA ");
	}

	printf("%s\n", hostname);

	res	= _nss_dnsdc_gethostbyname2_r(hostname, af, &host, buf, BUFLEN,
			&errnop, &h_errnop);

	assert(res == NSS_STATUS_SUCCESS || res == NSS_STATUS_NOTFOUND);

	if (res == NSS_STATUS_NOTFOUND) {
		printf("\tNo data\n");
		return;
	}

	addr_list = (struct in_addr **)host.h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++) {
		inet_ntop(af, addr_list[i], buf, maxaddrlen);
		printf("\t%s\n", buf);
	}
}

int main(int argc, char **argv) {
	int i;

	if (argc == 1) {
		resolve("example.org", AF_INET, INET_ADDRSTRLEN);
		resolve("example.org", AF_INET6, INET6_ADDRSTRLEN);
		return 0;
	}

	for (i=1; i<argc;i++) {
		resolve(argv[i], AF_INET, INET_ADDRSTRLEN);
		resolve(argv[i], AF_INET6, INET6_ADDRSTRLEN);
	}
	return 0;
}
