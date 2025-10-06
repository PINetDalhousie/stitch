#include "stitch.ebpf.h"

/*** MAPS ***/

/* Userspace comms */
BPF_RINGBUF_OUTPUT(output, 1);

/* Pivot detection */
BPF_TABLE("lru_hash", struct fid, struct flowStat, flowStats, DEFAULT_HASH_SIZE);
BPF_TABLE("lru_hash", u16, struct fid, socketIn, DEFAULT_HASH_SIZE);
BPF_TABLE("lru_hash", u32, struct fid, tgids, DEFAULT_HASH_SIZE);
BPF_TABLE("lru_hash", u16, struct fid, socketOut, DEFAULT_HASH_SIZE);
BPF_TABLE("lru_hash", u32, struct sock *, currSock, DEFAULT_HASH_SIZE);

/* Alert management */
BPF_TABLE("array", u32, u64, budget, 1);
BPF_TABLE("hash", struct fid_pair, u8, alertedOn, DEFAULT_HASH_SIZE);
BPF_TABLE("lru_hash", struct endpoint, u32, clusters, DEFAULT_HASH_SIZE);

/*
 PROCESS TRACING
*/
int kretprobe____x64_sys_execve(struct pt_regs *ctx)
{
  struct task_struct *task;
  struct fid *fid;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  task = (struct task_struct *)bpf_get_current_task();
  u32 ppid = task->real_parent->tgid;

  fid = tgids.lookup(&ppid);
  if (fid != 0)
  {
    tgids.update(&pid, fid);
  }

  return 0;
}

int kretprobe____x64_sys_clone(struct pt_regs *ctx)
{
  struct task_struct *task;
  struct fid *fid;

  task = (struct task_struct *)bpf_get_current_task();
  u32 ppid = task->parent->tgid;

  u32 child_pid = PT_REGS_RC(ctx);
  if (child_pid <= 0)
  {
    return 1;
  }

  fid = tgids.lookup(&ppid);
  if (fid != 0)
  {
    tgids.update(&child_pid, fid);
  }

  return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
  struct task_struct *task = (typeof(task))bpf_get_current_task();

  if (task != 0)
  {
    u32 pid = task->tgid;
    if (pid != 0)
      tgids.delete(&pid);
  }
  return 0;
}

/*
 INCOMING TCP ACCESS
*/
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
  struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  if (newsk == NULL)
    return 0;

  u16 dport = newsk->__sk_common.skc_dport; // remote port (i.e., client src)
  dport = bpf_ntohs(dport);

  struct fid *fid;

  fid = socketIn.lookup(&dport);
  if (fid != 0 && pid != 0)
  {
    tgids.update(&pid, fid);
  }

  return 0;
}

/*
 OUTGOING TCP ACCESS
*/
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  currSock.update(&pid, &sk);
  return 0;
};

int kretprobe__inet_hash_connect(struct pt_regs *ctx)
{
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // check if connection was successful
  int ret = PT_REGS_RC(ctx);
  if (ret != 0)
  {
    currSock.delete(&pid);
    return 0;
  }

  struct sock **skpp;
  skpp = currSock.lookup(&pid);
  if (skpp == 0)
  {
    return 0; // missed entry
  }

  struct sock *skp = *skpp;
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = sockp->inet_sport;
  sport = bpf_ntohs(sport);

  struct fid *fid;

  fid = tgids.lookup(&pid);
  if (fid != 0)
  {
    socketOut.update(&sport, fid);
  }

  currSock.delete(&pid);

  return 0;
}

/*
 INGRESS
*/
#define IP_TCP 6

int handle_ingress(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct fid fid = {};
  struct flowStat *fstat;

  if (data + sizeof(*eth) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    return XDP_PASS;

  iph = data + sizeof(*eth);

  if (iph->protocol == IP_TCP)
  {
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
      return XDP_PASS;

    tcph = data + sizeof(*eth) + sizeof(*iph);

    fid.address = iph->saddr ^ iph->daddr;
    fid.port = tcph->source ^ tcph->dest;
    fid.proto = iph->protocol;

    fstat = flowStats.lookup(&fid);

    if (fstat == NULL)
    {
      struct flowStat newStat;
      newStat.size = bpf_ntohs(iph->tot_len);
      newStat.arrival = bpf_ktime_get_ns();
      newStat.dir = INCOMING;
      flowStats.insert(&fid, &newStat);

      u16 tcp_src = bpf_ntohs(tcph->source);

      if (tcp_src != 0)
      {
        socketIn.update(&tcp_src, &fid);
      }

    }
    else
    {
      fstat->size += bpf_ntohs(iph->tot_len);
    }

    return XDP_PASS;
  }

  return XDP_PASS;
}

/*
 EGRESS
*/
int handle_egress(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct fid *in_fid;
  struct fid fid = {};
  struct flowStat *fstat;

  if (data + sizeof(*eth) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    return TC_ACT_OK;

  iph = data + sizeof(*eth);

  if (iph->protocol == IP_TCP)
  {
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
      return TC_ACT_OK;

    tcph = data + sizeof(*eth) + sizeof(*iph);

    fid.address = iph->saddr ^ iph->daddr;
    fid.port = tcph->source ^ tcph->dest;
    fid.proto = iph->protocol;

    fstat = flowStats.lookup(&fid);

    if (fstat == NULL)
    {
      struct flowStat newStat;
      newStat.size = bpf_ntohs(iph->tot_len);
      newStat.arrival = bpf_ktime_get_ns();
      newStat.dir = OUTGOING;
      flowStats.insert(&fid, &newStat);

      /* Clustering. We are counting the connections made to particular
        endpoints (so don't care about incoming). */
      struct endpoint ep = {};
      ep.dst = bpf_ntohl(iph->daddr) & IP_MASK;
      ep.dport = bpf_ntohs(tcph->dest);

      int zero = 0;
      u32 *count = clusters.lookup_or_try_init(&ep, &zero);

      if (count)
      {
        *(count) += 1;
      }
    }
    else
    {
      fstat->size += bpf_ntohs(iph->tot_len);
    }

    u16 sport = bpf_ntohs(tcph->source);
    in_fid = socketOut.lookup(&sport);

    if (in_fid != 0)
    {
      struct flowStat *in_stats = flowStats.lookup(in_fid);
      struct flowStat *curr_stats = flowStats.lookup(&fid);

      if (in_stats != NULL && curr_stats != NULL &&
          curr_stats->dir == OUTGOING && in_stats->dir == INCOMING &&
          in_fid->address != fid.address &&
          in_stats->arrival > curr_stats->arrival - TIME_NS &&
          in_stats->arrival < curr_stats->arrival &&
          abs(in_stats->size - curr_stats->size) < SIZE_B)
      {
        /* Check if we've alerted on this pair yet. */
        struct fid_pair fid_pair = {};
        fid_pair.in = *(in_fid);
        fid_pair.out = fid;

        u8* alerted = alertedOn.lookup(&fid_pair);

        if(alerted) 
        {
          return TC_ACT_OK;
        }

        u32 alert_count_idx = COUNT_IDX;
        u64* curr_alert_count = budget.lookup(&alert_count_idx);

        if (curr_alert_count)
        { 
          struct endpoint ep = {};
          ep.dst = bpf_ntohl(iph->daddr) & IP_MASK;
          ep.dport = bpf_ntohs(tcph->dest);

          int zero = 0;
          u32 *count = clusters.lookup_or_try_init(&ep, &zero);

          /* Report if we haven't seen much, or if something is particularly rare */
          if ((count && *(count) < SUS)) // *(curr_alert_count) < BUDGET || 
          {
            *(curr_alert_count) += 1;

            struct data_out data = {};

            data.init_addr = in_fid->address;
            data.init_port = in_fid->port;
            data.init_proto = in_fid->proto;
            data.init_sz = in_stats->size;
            data.init_tm = in_stats->arrival;

            data.res_addr = iph->daddr;
            data.res_port = bpf_ntohs(tcph->dest);
            data.res_proto = iph->protocol;
            data.res_sz = curr_stats->size;
            data.res_tm = curr_stats->arrival;

            output.ringbuf_output(&data, sizeof(data), 0);
            
            u8 zero = 0;
            alertedOn.insert(&fid_pair, &zero);
          }
        }
      }
    }

    return TC_ACT_OK;
  }

  return TC_ACT_OK;
}
