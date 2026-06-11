#!/usr/bin/env python3
"""filament job-runner — host CLI.

Submit a single declared job to a paired filament box and get artifacts + a
manifest back. Thin wrapper over filament_runner.RunnerBox.

Examples
--------
NVENC transcode (the worked example from the research doc), input.mov in ./in,
outputs into ./out:

  runner/runner_cli.py \\
    --host-cfg ~/.filament-jobrunner/host \\
    --dout-cfg ~/.filament-jobrunner/host-dout \\
    --remote-root '~/filament-jobs' --remote-inbox '~/filament-jobs/.inbox' \\
    --box-dout-cfg '~/filament-jobs/cfg-dout' \\
    --in ./in --out ./out \\
    --input input.mov --output out_720p.mp4 \\
    -- ffmpeg -y -hwaccel cuda -hwaccel_output_format cuda -i input.mov \\
       -vf scale_cuda=-2:720 -c:v h264_nvenc -preset p5 -b:v 5M -c:a aac \\
       -progress pipe:1 -nostats out_720p.mp4
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from filament_runner import FileRunnerBox, Job  # noqa: E402

DEFAULT_SERVER = "https://api.filament.autumated.com"


def main():
    ap = argparse.ArgumentParser(
        description="Submit a filament compute job (file-driven; no PTY) and fetch artifacts.")
    ap.add_argument("--server", default=os.environ.get("FILJOB_SERVER", DEFAULT_SERVER))
    ap.add_argument("--bin", default=os.environ.get("FILAMENT_BIN", "filament"))
    ap.add_argument("--host-cfg", required=True, help="host config dir (din+dout secrets)")
    ap.add_argument("--dout-cfg", required=True, help="host dout sink config dir (dout secret)")
    ap.add_argument("--remote-inbox", default="~/filament-jobs/.inbox", help="box din drop dir (informational)")
    ap.add_argument("--in", dest="indir", required=True, help="local dir holding the inputs")
    ap.add_argument("--out", dest="outdir", required=True, help="local dir for fetched outputs")
    ap.add_argument("--input", action="append", default=[], help="input filename (repeatable)")
    ap.add_argument("--output", action="append", default=[], help="declared output filename (repeatable)")
    ap.add_argument("--timeout", type=int, default=1800, help="per-job compute timeout (s)")
    ap.add_argument("--await-timeout", type=int, default=None,
                    help="overall host-side wait for results (default: job timeout + 600s)")
    ap.add_argument("--rclone-dest", default=None, help="optional R2 durability target, e.g. r2:reel/")
    ap.add_argument("--id", default=None, help="job id (default: auto)")
    # --relay is the WAN default; --no-relay for local/direct paths.
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--relay", dest="relay", action="store_true", default=True,
                   help="force TURN relay (default; robust over unstable WAN)")
    g.add_argument("--no-relay", dest="relay", action="store_false",
                   help="use the direct route (local loopback / good links)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- argv run in the box scratch dir")
    args = ap.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("provide the job command after `--`")

    job = Job.new(cmd=cmd, inputs=args.input, outputs=args.output,
                  timeout_s=args.timeout, rclone_dest=args.rclone_dest, id=args.id)
    rb = FileRunnerBox(
        petname_box_din="box-in",
        server=args.server, host_config_dir=args.host_cfg,
        host_dout_config_dir=args.dout_cfg, filament_bin=args.bin,
        remote_inbox=args.remote_inbox, relay=args.relay,
        send_timeout_s=max(args.timeout, 1800),
    )

    print(f"submitting {job.id}: {' '.join(cmd)}", file=sys.stderr)
    manifest = rb.run(job, local_input_dir=args.indir, local_output_dir=args.outdir,
                      overall_timeout_s=args.await_timeout)
    print(json.dumps(manifest, indent=2))
    return 0 if manifest and manifest.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
