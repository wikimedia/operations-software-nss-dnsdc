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
   
	res	= _nss_dnsdc_gethostbyname2_r("example.org",
			AF_INET, &host, buf, BUFLEN, &errnop, &h_errnop);

	assert(res == NSS_STATUS_SUCCESS);

	addr_list = (struct in_addr **)host.h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++) {
		printf("%s\n", inet_ntoa(*addr_list[i]));
	}

	return 0;
}
