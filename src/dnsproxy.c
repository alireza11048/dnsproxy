/*
 * Copyright 2014, Vietor Liu <vietor.liu at gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version. For full terms that can be
 * found in the LICENSE file.
 */

#include "dnsproxy.h"
#include "asciilogo.h"
#include <curl/curl.h>
#include "doh_lib.h"
#include <stdbool.h>

#ifndef VERSION
#define VERSION "development"
#endif

#define PACKAGE_SIZE 8192
#define CACHE_CLEAN_TIME (MIN_TTL / 2 + 1)

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

const char default_url[] = "https://free.shecan.ir/dns-query";

typedef struct {
	SOCKET sock;
	char buffer[PACKAGE_SIZE + sizeof(unsigned short)];
} LOCAL_DNS;

typedef struct {
	LOCAL_DNS local;
	CURLM *curl_multi;
} PROXY_ENGINE;

static PROXY_ENGINE g_engine;
static const int enable = 1;
static int disable_cache = 0;

static void process_doh_query(PROXY_ENGINE *engine, struct curl_slist *headers, const char* DoH_url)
{
	LOCAL_DNS *ldns;
	CURLM *curl_multi;
	DNS_HDR *hdr;
	DNS_QDS *qds;
	socklen_t addrlen;
	struct sockaddr_in source;
	char *pos, *head, *rear;
	char *buffer, domain[PACKAGE_SIZE];
	int size, dlen;
	unsigned char qlen;
	unsigned int ttl, ttl_tmp;
	unsigned short index, q_len, result_code = 0;

	ldns = &engine->local;
	curl_multi = engine->curl_multi;
	buffer = ldns->buffer + sizeof(unsigned short);

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(ldns->sock, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size <= (int)sizeof(DNS_HDR))
		return;

	hdr = (DNS_HDR*)buffer;
	q_len = 0;
	qds = NULL;
	head = buffer + sizeof(DNS_HDR);
	rear = buffer + size;
	if(hdr->qr != 0 || hdr->tc != 0 || ntohs(hdr->qd_count) != 1)
	{
		result_code = 1;
	}
	else 
	{
		dlen = 0;
		pos = head;
		while(pos < rear) 
		{
			qlen = (unsigned char)*pos++;
			if(qlen > 63 || (pos + qlen) > (rear - sizeof(DNS_QDS))) 
			{
				result_code = 1;
				break;
			}
			if(qlen > 0) 
			{
				if(dlen > 0)
					domain[dlen++] = '.';
				while(qlen-- > 0)
					domain[dlen++] = (char)tolower(*pos++);
			}
			else 
			{
				qds = (DNS_QDS*) pos;
				if(ntohs(qds->classes) != 0x01)
				{
					result_code = 4;
				}
				else 
				{
					pos += sizeof(DNS_QDS);
					q_len = pos - head;
				}
				break;
			}
		}
		domain[dlen] = '\0';
	}

	// checking that the query type is supported
	if(ntohs(qds->type) != DNS_TYPE_A && ntohs(qds->type) != DNS_TYPE_AAAA &&
	ntohs(qds->type) != DNS_TYPE_CNAME && ntohs(qds->type) != DNS_TYPE_NS && ntohs(qds->type) != DNS_TYPE_TXT)
	{
		result_code = 1;
	}

	if(result_code == 0) 
	{
		int still_running = 0;
		int queued;
		CURLMsg *msg;
		int rc;
		struct dnsentry d;
		int successful = 0;
		int repeats = 0;		

		memset(&d, 0, sizeof(struct dnsentry));
		initprobe(ntohs(qds->type), domain, DoH_url, curl_multi, 0, headers, 0, v46, NULL);
		curl_multi_perform(curl_multi, &still_running);		
		do 
		{
			CURLMcode mc; 
			int numfds;

			// wait for activity, timeout or "nothing"
			mc = curl_multi_wait(curl_multi, NULL, 0, 1000, &numfds);
			if(mc != CURLM_OK) 
			{
				fprintf(stderr, "curl_multi_wait() failed, code %d.\n", mc);
				break;
			}

			/* 'numfds' being zero means either a timeout or no file descriptors to
			wait for. Try timeout on first occurrence, then assume no file
			descriptors and no file descriptors to wait for means wait for 100
			milliseconds. */
			if(!numfds) 
			{
				repeats++; /* count number of repeated zero numfds */
				if(repeats > 1) 
				{
					WAITMS(10); /* sleep 10 milliseconds */
				}
			}
			else
				repeats = 0;

			curl_multi_perform(curl_multi, &still_running);
			while((msg = curl_multi_info_read(curl_multi, &queued))) 
			{
				if(msg->msg == CURLMSG_DONE) 
				{
					struct dnsprobe *probe;
					CURL *e = msg->easy_handle;
					curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &probe);

					/* Check for errors */
					if(msg->data.result != CURLE_OK) 
					{
						fprintf(stderr, "probe for %s failed: %s\n",
						type2name(probe->dnstype),
						curl_easy_strerror(msg->data.result));
						result_code = 1;
					}
					else
					{
						long response_code;
						curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &response_code);
						if((response_code / 100 ) == 2) 
						{
							rc = doh_decode(probe->serverdoh.memory,
											probe->serverdoh.size,
											probe->dnstype, &d);
							if(rc) 
							{
								if(rc == DOH_DNS_BAD_RCODE) 
								{
									fprintf(stderr, "Bad rcode, %s (%s)\n", domain, type2name(probe->dnstype));
								}
								else if(rc != DOH_NO_CONTENT) 
								{
									fprintf(stderr, "problem %d decoding %" FMT_SIZE_T
									" bytes response to probe for %s\n",
									rc, probe->serverdoh.size, type2name(probe->dnstype));
									result_code = 1;
								}
							}
							else
								successful++;
						}
						else 
						{
							fprintf(stderr, "Probe for %s got response: %03ld\n", type2name(probe->dnstype), response_code);
						}
						free(probe->serverdoh.memory);
					}
					curl_multi_remove_handle(curl_multi, e);
					curl_easy_cleanup(e);
					free(probe);
				}
			}
		} while(still_running);

		if(result_code == 0)
		{
			int size_of_valid_request_packet;
			printf("[%s]\n", domain);
			printf("TTL: %u secnds\n", d.ttl);
			for(int i=0; i < d.numv4; i++) 
			{
				printf("A: %d.%d.%d.%d\n",
					d.v4addr[i]>>24,
					(d.v4addr[i]>>16) & 0xff,
					(d.v4addr[i]>>8) & 0xff,
					d.v4addr[i] & 0xff);
			}

			//finding the query section size
			int index = sizeof(DNS_HDR);
			while(buffer[index] != 0)
			{
				index += buffer[index] + 1;
			}
			size_of_valid_request_packet = index + 5 /* 2byte query class + 2byte query type + 1byte current byte*/;

			char *response_buffer = malloc(size_of_valid_request_packet /* size of the */ + (2 /* response name */ + sizeof(DNS_RRS) + 4 /*size of the result ip*/) * d.numv4);
			memset(response_buffer, 0, size_of_valid_request_packet + (2 /* response name */ + sizeof(DNS_RRS) + 4) * d.numv4); 
			memcpy(response_buffer, buffer, size_of_valid_request_packet);
			
			// adjusting the response header
			DNS_HDR *response_hdr = response_buffer;
			response_hdr->qr = 1;
			response_hdr->aa = 0;
			response_hdr->tc = 0;
			response_hdr->ra = 1;
			response_hdr->ad = 0;
			response_hdr->rcode = 0;
			response_hdr->an_count = ntohs(d.numv4);
			response_hdr->ns_count = ntohs(0);
			response_hdr->nr_count = ntohs(0);
			
			// poitner to the query entry
			DNS_QDS *querey_entry = response_buffer + size_of_valid_request_packet - 4;

			int answer_entry_size = (2 /* response name */ + sizeof(DNS_RRS) + 4);
			int offset = 0;
			// adjusting the answer section
			// pointing to the query section
			for(int i = 0; i < d.numv4; i++)
			{
				response_buffer[size_of_valid_request_packet + offset] = 0xc0;
				response_buffer[size_of_valid_request_packet + offset + 1] = 0x0c;
				DNS_RRS *answer_entry = response_buffer + size_of_valid_request_packet + offset + 2;
				answer_entry->type = querey_entry->type;
				answer_entry->classes = querey_entry->classes;
				answer_entry->ttl = htonl(d.ttl);
				answer_entry->rd_length = htons(4);
				answer_entry->rd_data[0] = (d.v4addr[0]>>24) & 0xff;
				answer_entry->rd_data[1] = (d.v4addr[0]>>16) & 0xff;
				answer_entry->rd_data[2] = (d.v4addr[0]>>8) & 0xff;
				answer_entry->rd_data[3] = (d.v4addr[0]) & 0xff;
				offset += answer_entry_size;
			}
			sendto(ldns->sock, response_buffer, size_of_valid_request_packet + 2 /* response name */ + sizeof(DNS_RRS) + 4, 0, &source, sizeof(struct sockaddr_in));
			free(response_buffer);
		}
	}
	
	if(result_code != 0)
	{
		char rbuffer[PACKAGE_SIZE];
		DNS_HDR *rhdr;
		rhdr = (DNS_HDR*)rbuffer;
		rhdr->id = hdr->id;
		rhdr->qr = 1;
		rhdr->rcode = result_code;
		sendto(ldns->sock, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
	}
}

static int dnsproxy(unsigned short local_port, const char* DoH_url)
{
	int maxfd, fds;
	fd_set readfds;
	struct timeval timeout;
	struct sockaddr_in addr;
	time_t current, last_clean;
	struct curl_slist *headers = NULL;

#ifdef _WIN32
	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
#endif
	PROXY_ENGINE *engine = &g_engine;
	LOCAL_DNS *ldns = &engine->local;

	ldns->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(ldns->sock == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}
	setsockopt(ldns->sock, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(enable));
#ifdef _WIN32
	WSAIoctl(ldns->sock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
#endif
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(local_port);
	if(bind(ldns->sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind service port");
		return -1;
	}

	// initilizing the curl
	curl_global_init(CURL_GLOBAL_ALL);
	/* use the older content-type */
	headers = curl_slist_append(headers,
								"Content-Type: application/dns-message");
	headers = curl_slist_append(headers,
								"Accept: application/dns-message");

	engine->curl_multi = curl_multi_init();
	

	last_clean = time(&current);
	while(1) {
		FD_ZERO(&readfds);
		FD_SET(ldns->sock, &readfds);
		maxfd = (int)ldns->sock;

		/* if active probes are empty, waiting for a dns request */
		if(get_active_probe_count() == 0)
		{
			timeout.tv_sec = CACHE_CLEAN_TIME;
			timeout.tv_usec = 0;
			fds = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
			if(fds > 0) {
				if(FD_ISSET(ldns->sock, &readfds))
					process_doh_query(engine, headers, DoH_url);
			}	
		}

		
		if(time(&current) - last_clean > CACHE_CLEAN_TIME || fds == 0) {
			last_clean = current;
			domain_cache_clean(current);
			transport_cache_clean(current);
		}
	}
	return 0;
}

struct xoption options[] = {
	{'v', "version", xargument_no, NULL, -1},
	{'h', "help", xargument_no, NULL, -1},
	{'d', "daemon", xargument_no, NULL, -1},
	{'p', "port", xargument_required, NULL, -1},
	{'U', "DoH-server-url", xargument_no, NULL, -1},
	{'f', "hosts-file", xargument_required, NULL, -1},
	{0, "disable-cache", xargument_no, &disable_cache, 1},
	{0, NULL, xargument_no, NULL, 0},
};

static void display_help()
{
	printf("Usage: dnsproxy [options]\n"
		"  -d or --daemon\n"
		"                       (daemon mode)\n"
		"  -p <port> or --port=<port>\n"
		"                       (local bind port, default 8053)\n"
		"  -R <ip> or --remote-addr=<ip>\n"
		"                       (remote server ip, default 8.8.8.8)\n"
		"  -P <port> or --remote-port=<port>\n"
		"                       (remote server port, default 53)\n"
//		"  -T or --remote-tcp\n"
//		"                       (connect remote server in tcp, default no)\n"
		"  -f <file> or --hosts-file=<file>\n"
		"                       (user-defined hosts file)\n"
		"  -h, --help           (print help and exit)\n"
		"  -v, --version        (print version and exit)\n");
};

int main(int argc, const char* argv[])
{
#ifdef _WIN32
	WSADATA wsaData;
#endif
	int opt, optind;
	const char *optarg;
	int use_daemon = 0;
	int transport_timeout = 5;
	const char *hosts_file = NULL;
	const char *DoH_url = default_url;
	unsigned short local_port = 8053;

	optind = 0;
	opt = xgetopt(argc, argv, options, &optind, &optarg);
	while(opt != -1) {
		switch(opt) {
		case 0:
			break;
		case 'p':
			local_port = (unsigned short)atoi(optarg);
			break;
		case 'U':
			DoH_url = optarg;
			break;
		case 'f':
			hosts_file = optarg;
			break;
		case 'd':
			use_daemon = 1;
			break;
		case 'v':
			printf("%s"
				" * version: %s\n",
				ascii_logo,
				VERSION);
			return 0;
		case 'h':
		default:
			display_help();
			return -1;
		}
		opt = xgetopt(argc, argv, options, &optind, &optarg);
	}

#ifdef _WIN32
	WSAStartup(MAKEWORD(2,2), &wsaData);
	if(use_daemon) {
		freopen("NUL", "r", stdin);
		freopen("NUL", "w", stdout);
		freopen("NUL", "w", stderr);
		FreeConsole();
	}
#else
	if(use_daemon) {
		int fd;
		pid_t pid = fork();
		if(pid < 0) {
			perror("fork");
			return -1;
		}
		if(pid != 0)
			exit(0);
		pid = setsid();
		if(pid < -1) {
			perror("setsid");
			return -1;
		}
		chdir("/");
		fd = open ("/dev/null", O_RDWR, 0);
		if(fd != -1) {
			dup2 (fd, 0);
			dup2 (fd, 1);
			dup2 (fd, 2);
			if(fd > 2)
				close (fd);
		}
		umask(0);
	}
	signal(SIGPIPE, SIG_IGN);
#endif

	printf("%s"
		" * runing at %d%s\n"
		" * DoH server %s\n"
		, ascii_logo
		, local_port
		, disable_cache? ", cache: off": ""
		, DoH_url);

	srand((unsigned int)time(NULL));
	domain_cache_init(hosts_file);
	transport_cache_init(transport_timeout);
	return dnsproxy(local_port, DoH_url);
}
