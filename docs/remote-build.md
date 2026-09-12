# Remote builds

The dev box is small (2 cores, 5 GB), so filament compiles elsewhere. Two paths,
one default and one reserve.

## Default: GitHub Actions (free, no quota)

`scripts/rbuild.sh` dispatches `.github/workflows/build-remote.yml`, waits, and
downloads the binary. Public repo, so runner minutes, cache and artifacts cost
nothing. The runner is 4 cores / 16 GB and shares sccache with CI, so a build of
a branch CI has already seen is mostly cache hits.

    scripts/rbuild.sh                        # current branch, musl release -> out/rbuild/filament
    scripts/rbuild.sh --ref main --out ~/.local/bin
    scripts/rbuild.sh --profile dev --test   # also cargo test
    scripts/rbuild.sh -- --locked            # extra cargo args after --

It builds what is on GitHub. Uncommitted or unpushed work on the current branch
makes it refuse (exit 3); push first or pass `--force`. Latency floor is about a
minute of queue plus checkout and cache restore before cargo starts, so it suits
"build this branch", not a tight edit-compile loop.

Artifacts keep for 7 days (`--retention N` to change). Each download writes
`BUILD_INFO` next to the binary with sha, ref, target, build seconds and run URL.

## Reserve: one Codespace (metered, 120 core-hours/month on Free)

`scripts/cs.sh` reuses ONE existing Codespace (the 4-core Egregoria machine,
`effective-spoon-pg59gwpxj6cxv5`) for interactive work Actions cannot do:
debugging, a live binary, a fast loop. filament is cloned on its disk at
`/workspaces/filament`, so `target/` survives stops and builds stay incremental.

    scripts/cs.sh status
    scripts/cs.sh run --ref my-branch      # up, build, fetch to out/cs/, down
    scripts/cs.sh up && scripts/cs.sh sh   # interactive
    scripts/cs.sh sync                     # rsync uncommitted tree to the remote
    scripts/cs.sh down                     # stop the meter

Rules: never create a second Codespace; always `down` when done (the 30 min idle
timeout is the safety net, not the plan); `cs.sh clean` frees the Egregoria and
filament `target/` dirs if the 32 GB disk fills. Stopped disks still count
against storage (15 GB-months on Free). A Codespace idle 30 days is deleted with
its caches; source is in git, so that only costs one cold build.
