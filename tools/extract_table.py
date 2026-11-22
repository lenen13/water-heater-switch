"""从 waterctl 的 deputy.wat 中提取 2096 字节查找表，写成二进制表文件。

原始实现把核心 key 算法藏在 WebAssembly 里（deputy.wat -> deputy.wasm），
但 WAT 是文本，data 段里的 \\xx 转义就是原始字节，直接抽出来即可。

用法:
    python tools/extract_table.py

产物:
    py/deputy_table.bin   (2096 字节)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "waterctl-2.x" / "src" / "deputy.wat"
OUT = ROOT / "py" / "deputy_table.bin"

EXPECTED_LEN = 2096


def main() -> int:
    text = SRC.read_text(encoding="utf-8")
    start = text.index("(data (i32.const 0)")
    end = text.index("(func $DEPUTY")
    segment = text[start:end]

    data = bytes(int(m.group(1), 16) for m in re.finditer(r"\\([0-9a-fA-F]{2})", segment))
    if len(data) != EXPECTED_LEN:
        print(f"unexpected table length: {len(data)} (want {EXPECTED_LEN})", file=sys.stderr)
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"wrote {OUT} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
