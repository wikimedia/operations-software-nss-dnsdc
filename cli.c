#include <stdio.h>
#include <unistd.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "nss-dnsdc.h"

#define BUFLEN 2048

int main() {
	struct hostent host;
	char buf[BUFLEN];
	int errnop, h_errnop;
	enum nss_status res;
   
    res	= _nss_dnsdc_gethostbyname2_r("example.org",
			AF_INET, &host, buf, BUFLEN, &errnop, &h_errnop);

	printf("res=%d\n", res);
	return 0;
}
