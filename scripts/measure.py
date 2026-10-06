#!/usr/bin/env python3
"""Run a benchmark and report whole-workload CPU and peak child RSS (Linux)."""
import resource
import subprocess
import sys
import time

started = time.monotonic()
result = subprocess.run(sys.argv[1:], check=False)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(f"workload wall_s={time.monotonic()-started:.3f} user_cpu_s={usage.ru_utime:.3f} "
      f"system_cpu_s={usage.ru_stime:.3f} peak_child_rss_kib={usage.ru_maxrss}")
sys.exit(result.returncode)
