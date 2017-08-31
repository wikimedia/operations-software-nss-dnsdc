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
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ares.h>
#include <ares_dns.h>

#ifdef LOGGING
#include <syslog.h>
#endif

//#include "dnsdc.h"

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv-dnsdc.conf"
#endif

const int n_servers = 3;
const char *nameservers[] = {"8.8.4.1", "8.8.8.8", "127.0.0.53"};
int timeouts[] = { 500, 100, 5 };
int attempts = 2;

// From NSS-Modules-Interface.html
// Possible return values follow. The correct error code must be stored in *errnop.
// NSS_STATUS_TRYAGAIN  EAGAIN	One of the functions used ran temporarily out of resources or a service is currently not available.
//                      ERANGE	The provided buffer is not large enough. The function should be called again with a larger buffer.
// NSS_STATUS_UNAVAIL   ENOENT	A necessary input file cannot be found. (?!)
// NSS_STATUS_NOTFOUND  ENOENT	The requested entry is not available.
//
static enum nss_status
getanswer_one(const char *nameserver, int fd, int timeout, const char *name, char *buffer,
		size_t buflen, int af, int *errnop, int *h_errnop,
		struct hostent *result, int32_t *ttlp)
{
	// class = 1 (Internet)
	// recursion desired = yes
	int qtype, dnsclass = 1, rd = 1, max_udp_size = 512;
	int pkt_buflen;
	int res_parse_reply = ARES_SUCCESS;
	unsigned char *pkt_buf;
	unsigned char dnspkg[512];
	int saddr_buf_len;
	unsigned short id = rand() % 65536;
	struct sockaddr_in dns_server;
	struct hostent *resolved_host = NULL;
	struct timeval tv;

	// See __ns_type in arpa/nameser.h
	switch (af) {
		case AF_INET:
			// qtype = A
			qtype = ns_t_a;
			break;
		case AF_INET6:
			// qtype = AAAA
			qtype = ns_t_aaaa;
			break;
		default:
			return NSS_STATUS_UNAVAIL;
	}

	syslog(LOG_DEBUG, "getanswer_one(nameserver=%s, fd=%d, timeout=%d, name=%s, af=%d, buflen=%lu)\n", nameserver, fd, timeout, name, af, buflen);

	// Create DNS query
	// ARES_SUCCESS, ARES_EBADNAME, ARES_ENOMEM are the possible return values
	if ((ares_create_query(name, dnsclass, qtype, id, rd,
		&pkt_buf, &pkt_buflen, max_udp_size)) != ARES_SUCCESS) {
		return NSS_STATUS_UNAVAIL;
	}

	// Send
	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(53);
	inet_pton(AF_INET, nameserver, &dns_server.sin_addr);

	if (sendto(fd, pkt_buf, pkt_buflen, 0, (struct sockaddr *)&dns_server,
		sizeof(dns_server)) != pkt_buflen) {
		ares_free_string(pkt_buf);
		return NSS_STATUS_UNAVAIL;
	}

	ares_free_string(pkt_buf);

	// Set receive timeout in ms
	tv.tv_sec = 0;
	tv.tv_usec = timeout * 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		return NSS_STATUS_UNAVAIL;
	}

	// Recieve
	saddr_buf_len = recv(fd, dnspkg, sizeof(dnspkg), 0);

	if (saddr_buf_len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		*errnop = ETIMEDOUT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	// check return value here (eg: saddr_buf_len < 0 NODATA, < 12 NOHDR, ...)
	//printf("saddr_buf_len: %d\n", saddr_buf_len);

	if (qtype == ns_t_a) {
		res_parse_reply = ares_parse_a_reply(dnspkg, saddr_buf_len, &resolved_host,
				NULL, NULL);
	} else if (qtype == ns_t_aaaa) {
		res_parse_reply = ares_parse_aaaa_reply(dnspkg, saddr_buf_len, &resolved_host,
				NULL, NULL);
	}

	if (res_parse_reply == ARES_ENODATA) {
		return NSS_STATUS_NOTFOUND;
	}

	if (id != DNS_HEADER_QID(dnspkg)) {
		syslog(LOG_DEBUG, "getanswer_one(nameserver=%s, name=%s, af=%d) response Query ID %d !=request Query ID %d\n", nameserver, name, af, DNS_HEADER_QID(dnspkg), id);
		return NSS_STATUS_UNAVAIL;
	}

	if (res_parse_reply != ARES_SUCCESS) {
		// Possible values here are: ARES_EBADRESP, ARES_ENOMEM
		return NSS_STATUS_UNAVAIL;
	}

	result->h_name = resolved_host->h_name;
	result->h_aliases = resolved_host->h_aliases;
	result->h_length = resolved_host->h_length;
	result->h_addr_list = resolved_host->h_addr_list;

	return NSS_STATUS_SUCCESS;
}

static enum nss_status
getanswer_r(const char *name, char *buffer,
		size_t buflen, int af, int *errnop, int *h_errnop,
		struct hostent *result, int32_t *ttlp)
{
	int i, fd, attempt;
	enum nss_status status = NSS_STATUS_UNAVAIL;

	// Create socket
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return NSS_STATUS_UNAVAIL;

	for (attempt=0; attempt<attempts; attempt++) {
		syslog(LOG_DEBUG, "getanswer_r(name=%s, af=%d) %d/%d attempts\n",
			name, af, attempt+1, attempts);

		for (i=0; i<n_servers; i++) {
			status = getanswer_one(nameservers[i], fd, timeouts[i], name, buffer,
					buflen, af, errnop, h_errnop, result, ttlp);

			if (status == NSS_STATUS_SUCCESS) {
			//if (*errnop != ETIMEDOUT) {
				*errnop=0;
				*h_errnop=1;
				syslog(LOG_DEBUG, "getanswer_r(name=%s, af=%d, server=%s(%i), timeout=%d) -> NSS_STATUS_%d", name, af, nameservers[i], i, timeouts[i], status);

				close(fd);
				return status;
			}
		}
	}

	syslog(LOG_DEBUG, "getanswer_r(name=%s, af=%d) -> NSS_STATUS_%d after going through all servers", name, af, status);

	close(fd);
	return status;
}

/*
enum nss_status _nss_dnsdc_gethostbyname4_r(
		const char *name, struct gaih_addrtuple **pat,
        char *buffer, size_t buflen, int *errnop,
        int *herrnop, int32_t *ttlp)
{
	//struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
	//char *r_name;
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname4_r has been invoked");
	return NSS_STATUS_UNAVAIL;
}
*/

enum nss_status _nss_dnsdc_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	/*
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname3_r(name=%s, af=%d, buflen=%lu)",
		name, af, buflen);
	*/
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname3_r(name=%s, af=%d, buflen=%lu)\n", name, af, buflen);
	return getanswer_r(name, buf, buflen, af, errnop, h_errnop, host, ttlp);
}

enum nss_status _nss_dnsdc_gethostbyname2_r(const char *name, int af,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return getanswer_r(name, buffer, buflen, af, errnop, h_errnop, host, NULL);
}

enum nss_status _nss_dnsdc_gethostbyname_r(const char *name,
		struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return getanswer_r(name, buffer, buflen, AF_INET, errnop, h_errnop, host, NULL);
}

enum nss_status _nss_dnsdc_gethostbyaddr2_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp)
{
	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_dnsdc_gethostbyaddr_r(const void* addr, socklen_t len,
		int af, struct hostent *host, char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
}

