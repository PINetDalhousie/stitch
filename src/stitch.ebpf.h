#ifndef __EBPF_HEADER_
#define __EBPF_HEADER_

#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/sched.h>

/*********
Constants
*********/

#ifndef SIZE_B
/* Size window in bytes */
#define SIZE_B 6500
#endif

#ifndef TIME_NS
/* Time window in ns */
#define TIME_NS 1000000000
#endif

/* Flow direction indicator */
#define INCOMING 0
/* Flow direction indicator */
#define OUTGOING 1

/* BCC default size for hashmaps */
#define DEFAULT_HASH_SIZE 10240

/* Indexer for budget map */
#define COUNT_IDX 0

/* BUDGET alerts per some period */
#define BUDGET 5

/* SUS THRESHOLD */
#ifndef SUS
#define SUS 10
#endif

/* Endpoint IP Mask, default 32-bits */
#ifndef IP_MASK
#define IP_MASK 0xFFFFFFFF
#endif

/*********
Structs
*********/

/* Outgoing flow destination */
struct endpoint
{
  u32 dst;
  u16 dport;
};

/* Flow ID */
struct fid
{
  u32 address;
  u16 port;
  u8 proto;
};

/* Tunneling FID pair */
struct fid_pair
{
  struct fid in;
  struct fid out;
};

/* Info about flow */
struct flowStat
{
  u32 size;
  u64 arrival;
  u8 dir;
};

/* Userspace message */
struct data_out
{
  u32 init_addr;
  u16 init_port;
  u8 init_proto;
  int init_sz;
  u64 init_tm;
  u32 res_addr;
  u16 res_port;
  u8 res_proto;
  int res_sz;
  u64 res_tm;
};

#endif
