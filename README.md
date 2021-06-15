# Kernel PWN Cheat Sheet

Some useful commands when doing kernel pwn challenges



Pack/Unpack rootfs

```bash
#pack
$ mkdir output
$ cd output
$ file rootfs.cpio 
rootfs.cpio: gzip compressed data, last modified: Tue Nov 12 01:43:34 2019, from Unix
/output$ cp ../rootfs.cpio rootfs.cpio.gz
/output$ gunzip rootfs.cpio.gz
/output$ cpio -idmv < rootfs.cpio
#unpack
/output$ find . | cpio -o --format=newc | gzip -c  > ../rootfs.cpio
```



Extract vmlinux from bzImage:

```bash
$ /usr/src/linux-headers-4.4.0-31/scripts/extract-vmlinux bzImage >> vmlinux
```



Check whether the environment KPTI is turned on:

If there is   `-cpu kvm64,+smep`  in the qemu startup script, it means that KPTI is enabled in the environment.

Or enter the following command after opening the challenge environment(root privilege required):

```bash
/ # dmesg | grep 'page table'
[    0.712632] Kernel/User page tables isolation: enabled
/ # cat /proc/cpuinfo | grep pti
fpu_exception	: yes
flags		: ... pti smep smap
```



gdb debug template (KASLR should be closed) ：

```shell
gdb \
	-ex 'set arch i386:x86-64' \
    -ex 'target remote localhost:1234'\
	-ex 'file vmlinux' \
    -ex 'add-symbol-file output/module.ko 0xffffffffc0002000'\ 
    #use 'cat /proc/modules | grep module' to find base address of target module.
```



Find the size of a structure in the kernel (source code needed):

```bash
$sudo apt install dwarves
$pahole -C packet_sock ./linux-5.6/vmlinux
die__process_function: tag not supported (INVALID)!
struct packet_sock {
	struct sock                sk;                   /*     0   752 */
	/* --- cacheline 11 boundary (704 bytes) was 48 bytes ago --- */
	struct packet_fanout *     fanout;               /*   752     8 */
	union tpacket_stats_u      stats;                /*   760    12 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 12 boundary (768 bytes) was 8 bytes ago --- */
	struct packet_ring_buffer  rx_ring;              /*   776   192 */
	/* --- cacheline 15 boundary (960 bytes) was 8 bytes ago --- */
	struct packet_ring_buffer  tx_ring;              /*   968   192 */
	/* --- cacheline 18 boundary (1152 bytes) was 8 bytes ago --- */
	int                        copy_thresh;          /*  1160     4 */
	spinlock_t                 bind_lock;            /*  1164     4 */
	struct mutex               pg_vec_lock;          /*  1168    32 */
	unsigned int               running;              /*  1200     4 */
	unsigned int               auxdata:1;            /*  1204:31  4 */
	unsigned int               origdev:1;            /*  1204:30  4 */
	unsigned int               has_vnet_hdr:1;       /*  1204:29  4 */
	unsigned int               tp_loss:1;            /*  1204:28  4 */
	unsigned int               tp_tx_has_off:1;      /*  1204:27  4 */

	/* XXX 27 bits hole, try to pack */

	int                        pressure;             /*  1208     4 */
	int                        ifindex;              /*  1212     4 */
	/* --- cacheline 19 boundary (1216 bytes) --- */
	__be16                     num;                  /*  1216     2 */

	/* XXX 6 bytes hole, try to pack */

	struct packet_rollover *   rollover;             /*  1224     8 */
	struct packet_mclist *     mclist;               /*  1232     8 */
	atomic_t                   mapped;               /*  1240     4 */
	enum tpacket_versions      tp_version;           /*  1244     4 */
	unsigned int               tp_hdrlen;            /*  1248     4 */
	unsigned int               tp_reserve;           /*  1252     4 */
	unsigned int               tp_tstamp;            /*  1256     4 */

	/* XXX 4 bytes hole, try to pack */

	struct completion          skb_completion;       /*  1264    32 */
	/* --- cacheline 20 boundary (1280 bytes) was 16 bytes ago --- */
	struct net_device *        cached_dev;           /*  1296     8 */
	int                        (*xmit)(struct sk_buff *); /*  1304     8 */

	/* XXX 32 bytes hole, try to pack */

	/* --- cacheline 21 boundary (1344 bytes) --- */
	struct packet_type         prot_hook;            /*  1344    64 */
	/* --- cacheline 22 boundary (1408 bytes) --- */
	atomic_t                   tp_drops;             /*  1408     4 */

	/* size: 1472, cachelines: 23, members: 29 */
	/* sum members: 1366, holes: 4, sum holes: 46 */
	/* bit holes: 1, sum bit holes: 27 bits */
	/* padding: 60 */
};
```



Find the address of a kernel function:

```
# cat /proc/kallsyms | grep "commit_creds"
# cat /proc/kallsyms | grep "prepare_kernel_cred"
```



Use ropper to get some useful gadgets:

```shell
$ ropper --file ./vmlinux --all --nocolor >> gadget
```



The exp file is too large after glibc static compilation:

We can use the musl library to compile, apt-get can be installed directly under ubuntu, or refer to [Official Website](https://www.musl-libc.org/how.html) to compile and install:

```bash
$ sudo apt-get install musl
$ sudo apt-get install musl-tools
```

Let's compare the file size after static compilation with gcc and musl-gcc:

```bash
$ musl-gcc exp2.c -o exp2 --static
$ ls -al | grep exp2
-rwxr-xr-x  1 ivan ivan  50800 Jan 13 03:44 exp2
$ gcc exp2.c -o exp2 --static
$ ls -al | grep exp2
-rwxr-xr-x  1 ivan ivan 859080 Jan 13 18:16 exp2
```



Remote interactive python script template:

```python
#!/usr/bin/env python2
from __future__ import print_function
from pwn import *
import sys
#context.proxy = (socks.SOCKS5,'test',9381)

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    conn = remote(host, port)
    PROMPT = b"/ $ "
    result = conn.recvuntil(PROMPT)
    print("Received before the first prompt:", result, file=sys.stderr)
    xblob = ""
    with open("./poc.bz2", "r") as f:
      xblob = f.read()
    for line in xblob.encode('base64').split('\n'):
      conn.sendline("echo \"%s\" >> /tmp/x.bz2.64" % line)
      conn.recvuntil(PROMPT)
    print("Exploit blob %d bytes" % len(xblob.encode('base64')), file=sys.stderr)
    conn.sendline("base64 -d /tmp/x.bz2.64 > /tmp/x.bz2")
    conn.recvuntil(PROMPT)
    conn.sendline("bunzip2 /tmp/x.bz2")
    conn.recvuntil(PROMPT)
    conn.sendline("chmod 777 /tmp/x")
    conn.recvuntil(PROMPT)
    conn.sendline("ls -l /tmp")
    result = conn.recvuntil(PROMPT)
    print("ls -l /tmp:",result,file=sys.stderr)
    conn.sendline("/tmp/x")
    result = conn.recvuntil(b"/ # ")
    print("Catting flag..",file=sys.stderr)
    conn.sendline("cat /root/flag")
    result = conn.recvuntil(b"}")
    print("flag:",result)
    sys.exit(0)

if __name__ == '__main__':
    main()
```

