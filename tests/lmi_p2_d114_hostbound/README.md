# Host-bound runtime lock suite

These tests bind the tracked `config/lmi-p2-d114/fastboot-wsl-runtime-lock.json`
to the **real** host: they lstat the real usr-merge chain, hash the real
fastboot executable, interpreter, and library closure, and execute the real
loader for the locked `--version` / `dpkg-query` transcripts.

They can only pass on the maintainer host whose runtime the lock was captured
from. `scripts/59_release_static_ci.sh` and the public workflow intentionally
do **not** run this directory; the portable accept-path coverage lives in
`tests/lmi_p2_d114` on top of `runtime_lock_fixture.synthetic_runtime_host`,
which derives the host view from the lock itself.

Run before a deploy, after any host toolchain change, or after re-pinning the
lock:

```
python3 -m unittest discover -s tests/lmi_p2_d114_hostbound
```

A failure here means the host drifted from the lock (for example a glibc
update moving the ELF interpreter). That is a signal to re-establish trust in
the deploy toolchain and have the owner re-capture the lock — never to edit
the pinned lock in place.
