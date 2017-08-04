/*
 *  This file is part of dnsdc.
 *
 *  dnsdc is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  dnsdc is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with dnsdc.  If not, see <http://www.gnu.org/licenses/>.
 */


/* GLIBC nss module */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <ares.h>

#ifdef LOGGING
#include <syslog.h>
#endif

//#include "dnsdc.h"

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv-dnsdc.conf"
#endif

/*
enum nss_status _nss_dnsdc_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
        char *buffer, size_t buflen, int *errnop,
        int *herrnop, int32_t *ttlp)
{
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname4_r has been invoked");
	return NSS_STATUS_UNAVAIL;
}
*/

// From NSS-Modules-Interface.html
// Possible return values follow. The correct error code must be stored in *errnop.
// NSS_STATUS_TRYAGAIN  EAGAIN	One of the functions used ran temporarily out of resources or a service is currently not available.
//                      ERANGE	The provided buffer is not large enough. The function should be called again with a larger buffer.
// NSS_STATUS_UNAVAIL   ENOENT	A necessary input file cannot be found. (?!)
// NSS_STATUS_NOTFOUND  ENOENT	The requested entry is not available.
//
enum nss_status _nss_dnsdc_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	// class = 1 (Internet)
	// qtype = A
	// recursion desired = yes
	int fd, dnsclass = 1, qtype = 1, rd = 1, max_udp_size = 512;
	int pkt_buflen;
	unsigned char *pkt_buf;
	unsigned char dnspkg[512];
	int saddr_buf_len;
	unsigned short id = 1;
	struct sockaddr_in dns_server;
	struct hostent *resolved_host;

	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname3_r has been invoked");

	// Create socket
	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(53);
	inet_pton(AF_INET, "127.0.0.53", &dns_server.sin_addr);

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return NSS_STATUS_UNAVAIL;

	//setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	// Create DNS query
	// ARES_SUCCESS, ARES_EBADNAME, ARES_ENOMEM are the possible return values
	if ((ares_create_query(name, dnsclass, qtype, id, rd,
		&pkt_buf, &pkt_buflen, max_udp_size)) != ARES_SUCCESS)
		return NSS_STATUS_UNAVAIL;

	// Send
	if (sendto(fd, pkt_buf, pkt_buflen, 0, (struct sockaddr *)&dns_server,
		sizeof(dns_server)) != pkt_buflen) {
		ares_free_string(pkt_buf);
		close(fd);
		return NSS_STATUS_UNAVAIL;
	}

	ares_free_string(pkt_buf);

	// Recieve
	saddr_buf_len = recvfrom(fd, dnspkg, sizeof(dnspkg), 0, NULL, NULL);
	close(fd);
	// check return value here (eg: saddr_buf_len < 0 NODATA, < 12 NOHDR, ...)
	//printf("saddr_buf_len: %d\n", saddr_buf_len);

	if ((ares_parse_a_reply(dnspkg, saddr_buf_len, &resolved_host,
			//&addrttls, &naddrttls)) != ARES_SUCCESS) {
			NULL, NULL)) != ARES_SUCCESS) {
		return NSS_STATUS_UNAVAIL;
	}

	host->h_name = resolved_host->h_name;
	host->h_aliases = resolved_host->h_aliases;
	host->h_length = resolved_host->h_length;
	host->h_addr_list = resolved_host->h_addr_list;

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dnsdc_gethostbyname2_r(const char *name, int af,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_dnsdc_gethostbyname3_r(name, af, host, buffer, buflen,
			errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dnsdc_gethostbyname_r(const char *name,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_dnsdc_gethostbyname3_r(name, AF_INET, host, buffer, buflen,
			errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dnsdc_gethostbyaddr2_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp)
{
	/* pacify compiler */
	(void) addr;
	(void) len;
	(void) af;
	(void) host;
	(void) buffer;
	(void) buflen;
	(void) ttlp;

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_dnsdc_gethostbyaddr_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	/* pacify compiler */
	(void) addr;
	(void) len;
	(void) af;
	(void) host;
	(void) buffer;
	(void) buflen;

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

