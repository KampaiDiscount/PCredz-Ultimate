# Upstream relationship

The original project is **PCredz**, created by Laurent Gaffié:

- Repository: `https://github.com/lgandx/PCredz`
- License: GNU General Public License v3.0
- Default branch: `master`
- Upstream reference reviewed for this repository pack: `a07051d392b50bded1a19734cb70f97010cd90a5`
- Reference date: 2026-07-29

PCredz Ultimate is an independently modified and substantially rewritten derivative. It is not an official release by the original author.

## Recommended remotes

A GitHub fork should use:

```text
origin    your GitHub fork
upstream  https://github.com/lgandx/PCredz.git
```

Verify with:

```bash
git remote -v
```

Fetch upstream without automatically merging it into the rewritten codebase:

```bash
git fetch upstream --tags --prune
```

Because the implementation has diverged substantially, review upstream changes selectively. Do not blindly merge `upstream/master` into `main`; use a topic branch and port relevant fixes with tests.
