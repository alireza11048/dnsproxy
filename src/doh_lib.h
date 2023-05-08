#ifndef _DOH_LIB_
#define _DOH_LIB_

#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28

#define MAX_ADDR 8
#define MAX_URLS 100

#define DNS_CLASS_IN 0x01

#include <stdbool.h>
#include <netinet/in.h>

typedef enum {
  DOH_OK,
  DOH_DNS_BAD_LABEL,    /* 1 */
  DOH_DNS_OUT_OF_RANGE, /* 2 */
  DOH_DNS_CNAME_LOOP,   /* 3 */
  DOH_TOO_SMALL_BUFFER, /* 4 */
  DOH_OUT_OF_MEM,       /* 5 */
  DOH_DNS_RDATA_LEN,    /* 6 */
  DOH_DNS_MALFORMAT,    /* 7 - wrong size or bad ID */
  DOH_DNS_BAD_RCODE,    /* 8 - no such name */
  DOH_DNS_UNEXPECTED_TYPE,  /* 9 */
  DOH_DNS_UNEXPECTED_CLASS, /* 10 */
  DOH_NO_CONTENT            /* 11 */
} DOHcode;

struct data {
  char trace_ascii; /* 1 or 0 */
};



struct response {
  unsigned char *memory;
  size_t size;
};

struct addr6 {
  unsigned char byte[16];
};

struct cnamestore {
  size_t len;       /* length of cname */
  char *alloc;      /* allocated pointer */
  size_t allocsize; /* allocated size */
};

struct txtstore {
  int len;
  char txt[255];
};

struct dnsentry {
  unsigned int ttl;
  int numv4;
  unsigned int v4addr[MAX_ADDR];
  int numv6;
  struct addr6 v6addr[MAX_ADDR];
  int numcname;
  struct cnamestore cname[MAX_ADDR];
  int numtxt;
  struct txtstore txt[MAX_ADDR];
};

static const char *type2name(int dnstype)
{
  switch(dnstype) {
  case DNS_TYPE_A: return "A";
  case DNS_TYPE_NS: return "NS";
  case DNS_TYPE_CNAME: return "CNAME";
  case DNS_TYPE_TXT: return "TXT";
  case DNS_TYPE_AAAA: return "AAAA";
  }
  return "Unknown";
}

enum iptrans { v4, v6, v46 };

typedef struct doh_status_t
{
  /* data */
  int probe_count;
}doh_status;

typedef struct dns_request_info_t{
	int size_of_valid_request_packet;
	char* response_buffer;
	struct sockaddr_in source;
}dns_request_info;

/* one of these for each http request */
struct dnsprobe {
  CURL *curl;
  int dnstype;
  unsigned char dohbuffer[512];
  size_t dohlen;
  struct response serverdoh;
  struct data config;
  dns_request_info* request_info;
};

int initprobe(int dnstype, char *host, const char *url, CURLM *multi,
                     int trace_enabled, struct curl_slist *headers,
                     bool insecure_mode, enum iptrans transport,
                     struct curl_slist *resolve, dns_request_info *request_info);

DOHcode doh_decode(unsigned char *doh,
                          size_t dohlen,
                          int dnstype,
                          struct dnsentry *d);

#endif
