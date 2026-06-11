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
from filament_runner import RunnerBox, Job  # noqa: E402

DEFAULT_SERVER = "https://api.filament.autumated.com"


def main():
    ap = argparse.ArgumentParser(description="Submit a filament compute job and fetch artifacts.")
    ap.add_argument("--server", default=os.environ.get("FILJOB_SERVER", DEFAULT_SERVER))
    ap.add_argument("--bin", default=os.environ.get("FILAMENT_BIN", "filament"))
    ap.add_argument("--host-cfg", required=True, help="host config dir (ctl+din+dout secrets)")
    ap.add_argument("--dout-cfg", required=True, help="host dout sink config dir (dout secret)")
    ap.add_argument("--remote-root", default="~/filament-jobs", help="box jobs root")
    ap.add_argument("--remote-inbox", default="~/filament-jobs/.inbox", help="box din drop dir")
    ap.add_argument("--box-dout-cfg", default="~/filament-jobs/cfg-dout", help="box dout-only config dir")
    ap.add_argument("--in", dest="indir", required=True, help="local dir holding the inputs")
    ap.add_argument("--out", dest="outdir", required=True, help="local dir for fetched outputs")
    ap.add_argument("--input", action="append", default=[], help="input filename (repeatable)")
    ap.add_argument("--output", action="append", default=[], help="declared output filename (repeatable)")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--rclone-dest", default=None, help="optional R2 durability target, e.g. r2:reel/")
    ap.add_argument("--id", default=None, help="job id (default: auto)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- argv run in the box scratch dir")
    args = ap.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("provide the job command after `--`")

    job = Job.new(cmd=cmd, inputs=args.input, outputs=args.output,
                  timeout_s=args.timeout, rclone_dest=args.rclone_dest, id=args.id)
    rb = RunnerBox(
        petname_ctl="box", petname_din="box-in", petname_dout="box-out",
        server=args.server, host_config_dir=args.host_cfg, filament_bin=args.bin,
        box_petname_for_host_dout="host-out",
        remote_jobs_root=args.remote_root, remote_inbox=args.remote_inbox,
        box_dout_config_dir=args.box_dout_cfg,
    )

    def on_progress(ev):
        if ev.kind == "progress":
            f = ev.data.get("frame"); t = ev.data.get("out_time"); fps = ev.data.get("fps")
            sys.stderr.write(f"\r  progress: frame={f} out_time={t} fps={fps}   ")
            sys.stderr.flush()
        elif ev.kind in ("begin", "done"):
            sys.stderr.write(f"\n  [{ev.kind}] {ev.data or ''}\n")

    print(f"submitting {job.id}: {' '.join(cmd)}", file=sys.stderr)
    manifest = rb.run(job, local_input_dir=args.indir, local_output_dir=args.outdir,
                      dout_config_dir=args.dout_cfg, on_progress=on_progress)
    print(json.dumps(manifest, indent=2))
    return 0 if manifest and manifest.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
