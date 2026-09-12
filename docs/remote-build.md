# Remote builds

The dev box is small (2 cores, 5 GB), so filament compiles elsewhere via
[rbuild](https://github.com/Abdk4Moura/rbuild). Defaults for this repo live in
`.rbuild` at the root (musl static release of `cli/`, binary `filament`).

    rbuild                          # build the current pushed branch on GitHub's free 4-core runner
    rbuild --ref main --out ~/.local/bin
    rbuild --profile measure        # functional iteration: opt 1, no LTO, roughly half the time
    rbuild --profile dev --test

Builds run in the rbuild repo's Actions, not here, so this repo's Actions view
stays CI-only. The binary lands in `~/.cache/rbuild/Abdk4Moura-filament/` with
a `BUILD_INFO` file. Actions builds what is pushed; dirty or unpushed work
makes `rbuild` refuse until you push or pass `--force`.

Expect about 5 minutes for a release build and 2 for `measure`; the release
floor is the fat-LTO single-codegen-unit link of the CLI crate, not
dependencies (those come from a shared R2 sccache plus a cached target dir).

For an interactive loop (debugging, a live binary) use the reserve Codespace,
which is metered, so stop it when done:

    rbuild cs run --ref my-branch   # up, build, fetch, down
    rbuild cs up && rbuild cs sh
    rbuild cs down

Install: `git clone https://github.com/Abdk4Moura/rbuild ~/rbuild && ~/rbuild/install.sh`
(needs `gh` with `repo`, `workflow`, `codespace` scopes and `jq`).
