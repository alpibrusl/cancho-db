"""What a durable commit of the M3 engine would cost in file writes (docs/m3-engine.md section 4), measured with the kernel's calls from Python, not with cancho.

    python3 scripts/measure_fsync.py [DIRECTORY]      # the directory is on the disk to measure; default: the current directory

Times (microseconds, minimum, median and 95th percentile of 300): a 4 KiB `pwrite` without a sync, with `fsync`, and the commit the design describes: the commit's records appended to a delta file and synced, three new
pages written to the page file and synced, then the superblock slot written and synced. It says what the DISK does here, not what cancho or the engine does: the engine is not written. The same file system as the
log directory is the one to measure, and a virtual disk may not honour a flush.
"""
import os
import sys
import statistics
import time
import tempfile
d = tempfile.mkdtemp(dir=sys.argv[1] if len(sys.argv) > 1 else ".")
def bench(name, fn, n=300):
    ts = []
    for i in range(n):
        t = time.perf_counter(); fn(i); ts.append((time.perf_counter() - t) * 1e6)
    ts.sort()
    print("%-62s min %7.1f  median %7.1f  p95 %7.1f us" % (name, ts[0], statistics.median(ts), ts[int(len(ts) * .95)]))
page = os.urandom(4096)
fd = os.open(d + "/pages", os.O_RDWR | os.O_CREAT, 0o644)
sup = os.open(d + "/super", os.O_RDWR | os.O_CREAT, 0o644)
dl = os.open(d + "/deltas", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
bench("pwrite 4 KiB, no sync", lambda i: os.pwrite(fd, page, (i % 64) * 4096))
bench("pwrite 4 KiB + fsync", lambda i: (os.pwrite(fd, page, (i % 64) * 4096), os.fsync(fd)))
def commit(i):                      # the engine's commit: deltas, 3 new pages, then the superblock, each synced in order
    os.write(dl, page[:200]); os.fsync(dl)
    for k in range(3): os.pwrite(fd, page, ((i * 3 + k) % 4096) * 4096)
    os.fsync(fd)
    os.pwrite(sup, page[:512], (i % 2) * 512); os.fsync(sup)
bench("engine commit: deltas + 3 pages + superblock, 3 fsyncs", commit)
def commit_nosuper(i):
    os.write(dl, page[:200]); os.fsync(dl)
    for k in range(3): os.pwrite(fd, page, ((i * 3 + k) % 4096) * 4096)
    os.fsync(fd)
bench("same without the superblock write (2 fsyncs)", commit_nosuper)
print("df type:", os.popen("df -T %s | tail -1" % d).read().strip())
import shutil
shutil.rmtree(d, ignore_errors=True)
