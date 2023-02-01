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

const char default_url[] = "https://free.shecan.ir/dns-query";

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

#endif
