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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef LOGGING
#include <syslog.h>
#endif

//#include "dnsdc.h"

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv-dnsdc.conf"
#endif

enum nss_status _nss_dnsdc_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
        char *buffer, size_t buflen, int *errnop,
        int *herrnop, int32_t *ttlp)
{
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname4_r has been invoked");
	return NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_dnsdc_gethostbyname3_r(const char *name, int af,
		struct hostent *host, char *buf, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
	syslog(LOG_INFO, "_nss_dnsdc_gethostbyname3_r has been invoked");
	return NSS_STATUS_UNAVAIL;
	/*
	unsigned int ttl;
	char sid;
	struct sockaddr_in **dnsservers = NULL;
	size_t nlen = 0;

	if (af == AF_INET &&
			(nlen = strlen(name)) > 0 &&
			buflen >= nlen + 1 + 2 * sizeof(void *) + sizeof(struct in_addr) + sizeof(void *) &&
			get_dnss_for_domain(&dnsservers, name) &&
			dnsq(dnsservers, name, (struct in_addr *)buf, &ttl, &sid) == 0)
	{
		host->h_addrtype = af;
		host->h_length = sizeof(struct in_addr);
		host->h_addr_list = (char **)buf + sizeof(struct in_addr);
		host->h_addr_list[0] = buf;
		host->h_addr_list[1] = NULL;
		host->h_aliases = (char **)&host->h_addr_list[2];
		host->h_aliases[0] = NULL;
		host->h_name = (char *)&host->h_aliases[1];
		memcpy(host->h_name, name, nlen + 1);
		if (ttlp != NULL)
			*ttlp = (int32_t)ttl;
		if (canonp != NULL)
			*canonp = host->h_name;

		*errnop = 0;
		*h_errnop = 0;
		return NSS_STATUS_SUCCESS;
	}

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;
	*/
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

