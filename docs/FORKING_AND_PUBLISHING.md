# Forking and publishing PCredz Ultimate

## Recommended GitHub workflow

1. Open `https://github.com/lgandx/PCredz` while signed in to GitHub.
2. Select **Fork** and choose your account or organization as the owner.
3. Rename the fork to `PCredz-Ultimate` if desired, and preserve the upstream relationship.
4. Clone your fork:

   ```bash
   git clone https://github.com/YOUR-USERNAME/PCredz-Ultimate.git
   cd PCredz-Ultimate
   ```

5. Confirm `origin` points to your fork and add the original project as `upstream`:

   ```bash
   git remote -v
   git remote add upstream https://github.com/lgandx/PCredz.git
   git fetch upstream --tags --prune
   ```

6. Create a dedicated import branch from your fork's default branch:

   ```bash
   git switch -c ultimate/3.1.0
   ```

7. From the Git kit directory, apply the prepared working tree:

   ```bash
   ./install-into-fork.sh /path/to/your/PCredz-Ultimate
   ```

8. Review the staged change before committing:

   ```bash
   cd /path/to/your/PCredz-Ultimate
   git status
   git diff --cached --stat
   git diff --cached
   ```

9. Commit and push:

   ```bash
   git commit -m "feat: import PCredz Ultimate 3.1.0"
   git push -u origin ultimate/3.1.0
   ```

10. On GitHub, either merge that branch into your fork's default branch or make it the long-lived development branch. Do not open a pull request against the original project unless the upstream maintainer has agreed to review a replacement-scale rewrite.

## Syncing upstream

Fetch periodically:

```bash
git fetch upstream --tags --prune
```

Inspect changes without merging:

```bash
git log --oneline --decorate main..upstream/master
git diff --stat main...upstream/master
```

Port relevant upstream fixes into a topic branch and add regression tests. The current codebase is structurally different enough that routine full-branch merges are likely to create misleading or destructive conflicts.

## Independent-repository alternative

A GitHub fork is excellent for provenance. A standalone repository can be clearer if the project becomes a separately governed product with a distinct roadmap. In that case:

- retain the complete GPLv3 license;
- retain `NOTICE.md` and `UPSTREAM.md`;
- state prominently that this is not an official PCredz release;
- keep an `upstream` remote for reference;
- avoid implying endorsement by the original author.
