#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 将输入的pcap文件等分为N个文件
// pcapsplit {pcapfile} {N}
// gcc -Wall -o pcapsplit pcapsplit.c -lpcap
//

// 用法
static int usage(void) {
  printf("pcapsplit {pcapfile} {n}\n\n");
  return 0;
}

struct wr_pcap {
  char fn[1024];
  pcap_t *pcap;
  pcap_dumper_t *dumper;
};

static struct wr_pcap *create_wr_pcap(char *fn, int idx) {
  char *dot;
  char fn_no_suffix[1024] = "";
  struct wr_pcap *outer;

  if (strlen(fn) >= 1024) {
    printf("create_wr_pcap: param fn length is too long!\n");
    return NULL;
  }

  outer = calloc(sizeof(*outer), 1);

  if (outer == NULL) {
    printf("malloc wr_pcap failed!\n");
    return NULL;
  }

  for (dot = fn + strlen(fn); *dot != '.' && dot != fn; dot --);
  if (dot == fn) {
    printf("invalid param fn\n");
    return NULL;
  }
  strncpy(fn_no_suffix, fn, dot - fn);

  snprintf(outer->fn, sizeof(outer->fn) - 1,  "%s-%d.pcap", fn_no_suffix, idx);
  outer->pcap = pcap_open_dead(1, 1600);
  if (outer->pcap == NULL) {
    printf("pcap open file failed!\n");
    free(outer);
    return NULL;
  }

  outer->dumper = pcap_dump_open(outer->pcap, outer->fn);
  if (outer->dumper == NULL) {
    printf("pcap dump open failed!\n");
    pcap_close(outer->pcap);
    free(outer);
    return NULL;
  }

  return outer;
}

static int write_wr_pcap(struct wr_pcap *outer, struct pcap_pkthdr *oh, unsigned char *pkt) {
  pcap_dump((unsigned char *)outer->dumper, oh, pkt);
  return 0;
}

static void close_wr_pcap(struct wr_pcap *outer) {
  pcap_close(outer->pcap);
  pcap_dump_close(outer->dumper);

  free(outer);
}

// argc == 2
int main(int argc, char *argv[]) {
  int i, n;
  int pkt_id;
  char fn[1024] = "";
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *pcapfn;
  struct wr_pcap **split_pcaps;

  int status;
  struct pcap_pkthdr *pkt_hdr = NULL;
  const unsigned char *pkt_data = NULL;

  if (argc != 3) {
    return usage();
  }

  strncpy(fn, argv[1], strlen(argv[1]));
  n = atoi(argv[2]);
  if (n < 2 || n >= 8) {
    printf("must split more than 2 files and less than 8 files!\n");
    return 0;
  }

  split_pcaps = malloc(n * sizeof(struct wr_pcap *));
  if (!split_pcaps) {
    printf("alloc pcap_t * failed!\n");
    return 0;
  }

  pcapfn = pcap_open_offline(fn, errbuf);
  if (pcapfn == NULL) {
    printf("open pcap file %s failed: %s\n", fn, errbuf);
    return -1;
  }
  for (i = 0; i < n; i ++) {
    split_pcaps[i] = create_wr_pcap(fn, i);
    if (split_pcaps[i] == NULL) {
      printf("create write pcap failed!\n");
      pcap_close(pcapfn);
      return -1;
    }
  }

  pkt_id = 0;
  status = pcap_next_ex(pcapfn, &pkt_hdr, &pkt_data);
  while(status == 1) {
    write_wr_pcap(split_pcaps[pkt_id%n], pkt_hdr, (unsigned char *)pkt_data);
    status = pcap_next_ex(pcapfn, &pkt_hdr, &pkt_data);
    pkt_id ++;
  }
  printf("split %d packets to %d files.\n", pkt_id, n);

  for(i = 0; i < n; i ++)
    close_wr_pcap(split_pcaps[i]);

  pcap_close(pcapfn);

  return 0;
}
