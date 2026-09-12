# Remote build defaults for https://github.com/Abdk4Moura/rbuild
# (`rbuild` builds on the free Actions runner; `rbuild cs` is the reserve Codespace.)
MANIFEST_DIR=cli
BIN=filament
TARGET=x86_64-unknown-linux-musl
CS=effective-spoon-pg59gwpxj6cxv5
CS_DIR=/workspaces/filament
# Dirs rbuild cs sync/dev skip: the build never reads them and they are most of the tree by bytes.
SYNC_EXCLUDE=experiments,frontend,docs,lab,showcase,spike,pake,deploy,packaging,proofs,runner
