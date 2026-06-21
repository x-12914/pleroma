#!/usr/bin/env python3
"""Filter a sensor dump CSV to rows whose _src_ip equals the attacker IP.

The sensor tags every dumped flow with a `_src_ip` column. Keeping only the
attacker's rows strips the public-IP background scan noise that a naive capture
window would otherwise mislabel — giving clean single-class training data.

Usage: filter_by_ip.py <in.csv> <out.csv> <attacker_ip>
"""
import csv
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    src, dst, ip = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(src, newline="", encoding="utf-8") as f, \
         open(dst, "w", newline="", encoding="utf-8") as g:
        r = csv.reader(f)
        w = csv.writer(g)
        try:
            header = next(r)
        except StopIteration:
            print("empty input")
            return 0
        w.writerow(header)
        if "_src_ip" not in header:
            # Older sensor without the IP column — pass through unfiltered.
            print("WARNING: no _src_ip column; copying unfiltered")
            for row in r:
                w.writerow(row)
            return 0
        idx = header.index("_src_ip")
        kept = total = 0
        for row in r:
            total += 1
            if len(row) > idx and row[idx] == ip:
                w.writerow(row)
                kept += 1
        print(f"kept {kept}/{total} rows from {ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
