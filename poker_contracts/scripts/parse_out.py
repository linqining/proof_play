#!/usr/bin/env python3
import sys, re
text = sys.stdin.read()
kind = sys.argv[1]
patterns = {
    "addr": r"CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)",
    "class": r"CLASS_HASH=(0x[0-9a-fA-F]+)",
    "tx": r"TX=(0x[0-9a-fA-F]+)",
    "already": r"(0x[0-9a-fA-F]{60,})",
}
m = re.search(patterns[kind], text)
print(m.group(1).lower() if m else "")
