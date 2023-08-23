#!/usr/bin/python

## This leverages eBPF and traces processes which writes to socket file types and writes greater than 
## <argument> KiloBytes
## Written By Soumendu Sekhar Satapathy
## Date: 22 August 2023
## satapathy.soumendu@gmail.com

from bcc import BPF
import re
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--size", help = "python3 trace_sock_file_types.py -s <bytes_written>")
args = parser.parse_args()
if args.size == None:
    print("python3 trace_sock_file_types.py -s <bytes_written>")
    sys.exit()

prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

#define WRITE_IO 1

/* 
  the key for the output
*/ 
struct key_t {
    unsigned long inode;
    int pid;
    int n_len;
    char proc[TASK_COMM_LEN];
    char name[DNAME_INLINE_LEN];
    char type[10];
};

/*
 the value for the output
*/
struct value_t {
    unsigned long rds;
    unsigned long wrts;
    unsigned long read_bytes;
    unsigned long write_bytes;
};

BPF_HASH(reports, struct key_t, struct value_t);

static int main_trace(struct pt_regs *ctx, struct file *file,
    char *buf, int bytes_w, int read_io)
{
    bpf_trace_printk("\nFile IO tracing per process...\n");
    int tgid = bpf_get_current_pid_tgid() >> 32;

    int pid = bpf_get_current_pid_tgid();

    struct dentry *d = file->f_path.dentry;
    int m = file->f_inode->i_mode;
    struct qstr d_name = d->d_name;
    if (d_name.len == 0)
        return 0;
    
    struct key_t key = {
        .pid = pid,
        .inode = file->f_inode->i_ino,
    };

    if (S_ISREG(m)) {
        strncpy(key.type,"REGULAR", strlen("REGULAR") + 1);
    } else if (S_ISSOCK(m)) {
        strncpy(key.type,"SOCKET", strlen("SOCKET") + 1);
    } else {
        strncpy(key.type,"OTHER", strlen("OTHER") + 1);
    }

    bpf_get_current_comm(&key.proc, sizeof(key.proc));
    key.n_len = d_name.len;
    bpf_probe_read_kernel(&key.name, sizeof(key.name), d_name.name);

    struct value_t *v;
    struct value_t updated_value = {0, 0 , 0 , 0};
    v = reports.lookup_or_try_init(&key, &updated_value);
    if (v) {
        v->wrts++;
        v->write_bytes += bytes_w;
    }

    return 0;
}

int write_trace(struct pt_regs *ctx, struct file *file,
    char *buf, int bytes_written)
{
    return main_trace(ctx, file, buf, bytes_written, WRITE_IO);
}

"""

b = BPF(text=prog)
b.attach_kprobe(event="vfs_write", fn_name="write_trace")

# Keep dumping output until terminated externally
while True:
    # Report the data collected
    reps = b.get_table("reports")
    for key, val in reps.items():

        type_str = re.search("SOCKET", key.type.decode('utf-8', 'replace'))
        con_type = re.search("UDP", key.name.decode('utf-8', 'replace'))
        if val.write_bytes > int(args.size) and type_str and con_type:
            print("PID: %-8d PROCESS: %-18s NO_WRITES: %-8d Write_kbytes %-6d FILE_TYPE: %s FILENAME: %s INODE: %-6d" % 
                   (key.pid, key.proc.decode('utf-8', 'replace'), val.wrts, val.write_bytes,
                       key.type.decode('utf-8', 'replace'), key.name.decode('utf-8', 'replace'), key.inode))
