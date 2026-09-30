#!/usr/bin/env python3
"""Drive a prompt/response command through a Unix pseudo-terminal."""

import json
import os
import pty
import select
import signal
import sys
import time


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[1] != "--responses":
        raise SystemExit("usage: compat-pty.py --responses JSON -- COMMAND [ARG ...]")
    responses = json.loads(sys.argv[2])
    separator = sys.argv.index("--", 3)
    command = sys.argv[separator + 1 :]
    if not command:
        raise SystemExit("missing command")

    child, descriptor = pty.fork()
    if child == 0:
        os.execvpe(command[0], command, os.environ)

    pending = list(responses)
    transcript = bytearray()
    deadline = time.monotonic() + float(os.environ.get("OATH_COMPAT_PTY_TIMEOUT", "120"))
    status = None
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([descriptor], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(descriptor, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    transcript.extend(chunk)
                    os.write(sys.stdout.fileno(), chunk)
                    visible = transcript.decode("utf-8", errors="replace")
                    while pending and pending[0][0] in visible:
                        _, response = pending.pop(0)
                        os.write(descriptor, f"{response}\n".encode())
                        transcript.clear()
                else:
                    break
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                break
        else:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            print("compat PTY command timed out", file=sys.stderr)
            return 124
    finally:
        os.close(descriptor)

    if status is None:
        _, status = os.waitpid(child, 0)
    if pending:
        print(f"unmatched prompts: {[prompt for prompt, _ in pending]}", file=sys.stderr)
        return 125
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    raise SystemExit(main())
