#!/usr/bin/python

## This leverages eBPF and traces processes whose write to files are greater than 10K KiloBytes 
## Written By Soumendu Sekhar Satapathy
## Date: 22 August 2023
## satapathy.soumendu@gmail.com

from bcc import BPF

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
    char proc[TASK_COMM_LEN];
    char name[DNAME_INLINE_LEN];
    int n_len;
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
    char __user *buf, int bytes_w, int read_io)
{
    bpf_trace_printk("\nFile IO tracing per process...\n");
    struct key_t key;
    int tgid = bpf_get_current_pid_tgid() >> 32;

    key.pid = bpf_get_current_pid_tgid();

    struct dentry *d = file->f_path.dentry;
    int m_type = file->f_inode->i_mode;
    struct qstr d_name = d->d_name;
    if (d_name.len == 0)
        return 0;
   
    // Populate the inode number.
    key.inode = file->f_inode->i_ino,

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

        if val.write_bytes > 10000:
            print("PID: %-8d PROCESS: %-18s NO_WRITES: %-8d Write_kbytes %-6d FILENAME: %s INODE: %-6d" % 
                   (key.pid, key.proc.decode('utf-8', 'replace'), 
                       val.wrts, val.write_bytes, key.name.decode('utf-8', 'replace'), key.inode))
