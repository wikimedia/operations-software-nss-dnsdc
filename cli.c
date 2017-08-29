#include <stdio.h>
#include <unistd.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>

#include "nss-dnsdc.h"

#define BUFLEN 2048

int main() {
	struct hostent host;
	char buf[BUFLEN];
	int errnop, h_errnop;
	enum nss_status res;
	struct in_addr **addr_list;
	int i;
   
	int af = AF_INET6;
	int maxaddrlen = INET6_ADDRSTRLEN;
	//int af = AF_INET;
	//int maxaddrlen = INET_ADDRSTRLEN;

	res	= _nss_dnsdc_gethostbyname2_r("example.org", af, &host, buf,
			BUFLEN, &errnop, &h_errnop);

	assert(res == NSS_STATUS_SUCCESS || res == NSS_STATUS_NOTFOUND);

	if (res == NSS_STATUS_NOTFOUND) {
		printf("No data\n");
		return 0;
	}

	addr_list = (struct in_addr **)host.h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++) {
		inet_ntop(af, addr_list[i], buf, maxaddrlen);
		printf("%s\n", buf);
	}

	return 0;
}
