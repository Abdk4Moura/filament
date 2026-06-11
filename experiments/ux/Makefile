# Filament e2e TEST + live-record pipeline — standard entry points.
# Run from experiments/ux/ (or `make -C experiments/ux <target>`).
#
#   make e2e         full suite (real app + real peers + reels)
#   make e2e-web     just the web e2e cases
#   make e2e-cli     just the cli↔cli scenarios
#   make e2e-runner  the loopback file-driven runner case
#   make e2e-fast    web suite, no recording, min quality (a quick gate)
#   make e2e-gpu     full suite forcing the high/NVENC quality tier
#   make help        pipeline flags

PIPE := ./pipeline.sh

.PHONY: e2e e2e-web e2e-cli e2e-runner e2e-fast e2e-gpu help

e2e:        ; $(PIPE) --suite all
e2e-web:    ; $(PIPE) --suite web
e2e-cli:    ; $(PIPE) --suite cli
e2e-runner: ; $(PIPE) --suite runner
e2e-fast:   ; $(PIPE) --suite web --no-record --quality min --sync
e2e-gpu:    ; $(PIPE) --suite all --quality high
help:       ; $(PIPE) --help
