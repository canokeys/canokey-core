# SPDX-License-Identifier: Apache-2.0
"""Run bounded libFuzzer smoke with a private writable corpus."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="canokey-fuzz-smoke-") as directory:
    corpus = Path(directory) / "corpus"
    shutil.copytree(sys.argv[2], corpus)
    subprocess.run([sys.argv[1], str(corpus), "-max_total_time=30", "-timeout=10",
                    "-print_final_stats=1"], check=True, timeout=60)
