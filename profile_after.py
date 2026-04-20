import requests, time

base = "http://localhost:8080"
scan_id = "scan_20260320_045824_69eb37"

# First load (cold - no cache)
t0 = time.perf_counter()
r1 = requests.get(f"{base}/api/results/{scan_id}")
t_first = time.perf_counter() - t0
print(f"First load (cold):  {t_first*1000:.0f}ms  status={r1.status_code}  size={len(r1.content)}")

# Second load (warm - cached)
t0 = time.perf_counter()
r2 = requests.get(f"{base}/api/results/{scan_id}")
t_second = time.perf_counter() - t0
print(f"Second load (warm): {t_second*1000:.0f}ms  status={r2.status_code}  size={len(r2.content)}")

# Third load (still cached)
t0 = time.perf_counter()
r3 = requests.get(f"{base}/api/results/{scan_id}")
t_third = time.perf_counter() - t0
print(f"Third load (warm):  {t_third*1000:.0f}ms  status={r3.status_code}  size={len(r3.content)}")

speedup = t_first / t_second if t_second > 0 else float('inf')
print(f"\nSpeedup: {speedup:.0f}x faster on repeat loads")
print(f"Savings: {(t_first - t_second)*1000:.0f}ms saved per page view")
