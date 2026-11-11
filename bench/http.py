#!/usr/bin/env python3
"""Measure verified HTTP round trips with already-built native backend binaries."""

import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return result


def native_path(path, windows):
    path = path.resolve()
    if windows and os.name != "nt":
        return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    return str(path)


def verify(text, backend, protocol, interface, count, samples, size):
    rows = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    expected = {"uring": "liburing", "ioring": "windows-io-ring"}.get(backend, backend)
    if len(rows) != 2 * samples:
        raise RuntimeError("each sample must contain both endpoint roles")
    for row in rows:
        if (row.get("backend") != expected or row.get("protocol") != protocol or
                row.get("interface") != interface or row.get("requests") != count or
                row.get("payload_bytes") != size or row.get("verified") is not True):
            raise RuntimeError("HTTP sample did not preserve the requested workload")
        if not math.isfinite(row["seconds"]) or row["seconds"] <= 0:
            raise RuntimeError("HTTP sample has no finite measurement interval")
        if row["role"] == "client" and not (isinstance(row.get("latency_p99_ns"), int) and row["latency_p99_ns"] > 0):
            raise RuntimeError("HTTP client sample has no p99 round-trip latency")
    clients = [row for row in rows if row["role"] == "client"]
    servers = [row for row in rows if row["role"] == "server"]
    for group in (clients, servers):
        if sorted(row["sample"] for row in group) != list(range(samples)):
            raise RuntimeError("HTTP sample identities are incomplete or repeated")
    return clients


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=root / "build/debug")
    parser.add_argument("--binaries", nargs="+", required=True, metavar="BACKEND=PATH")
    parser.add_argument("--bytes", type=positive, default=1024)
    parser.add_argument("--requests", type=positive, default=1000, help="minimum requests per sample and calibration request count")
    parser.add_argument("--warmup", type=positive, default=200)
    parser.add_argument("--seconds", type=float, default=2.0, help="target duration used to calibrate each condition")
    parser.add_argument("--samples", type=positive, default=5)
    parser.add_argument("--protocols", nargs="+", choices=("h1", "h2", "h3"), default=["h1", "h2", "h3"])
    parser.add_argument("--interfaces", nargs="+", choices=("coroutine", "execution"), default=["coroutine", "execution"])
    parser.add_argument("--timeout-seconds", type=positive, default=180)
    parser.add_argument("--build-label", default="Release")
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--windows-version", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if not build.is_dir() or not (build / "CMakeCache.txt").is_file():
        parser.error("--build-dir must be the existing configured project build directory")
    if not math.isfinite(args.seconds) or args.seconds <= 0:
        parser.error("--seconds must be positive and finite")
    binaries = {}
    for item in args.binaries:
        backend, separator, path = item.partition("=")
        if not separator or backend not in ("epoll", "uring", "iocp", "ioring", "kqueue") or backend in binaries:
            parser.error("each backend must name one binary")
        binaries[backend] = Path(path).resolve()
        if not binaries[backend].is_file():
            parser.error(f"binary does not exist: {path}")
    output = args.output.resolve() if args.output else build / "http-results.jsonl"
    if not output.parent.is_dir():
        parser.error("the results directory must already exist")
    state_path = build / "http-measurement-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    rows = []
    environment = os.environ.copy()
    environment["TMPDIR"] = str(build)
    cert, key = build / "quic-cert.pem", build / "quic-key.pem"

    for backend, binary in binaries.items():
        windows = binary.suffix.lower() == ".exe"
        address = "127.0.0.1" if windows or platform.system() != "Linux" else "127.0.0.2"
        metadata = dict(configured_backend=backend, host=platform.node(), machine=platform.machine(),
                        execution_os="Windows " + args.windows_version if windows else platform.platform(),
                        build=args.build_label, compiler=args.compiler, concurrency=1, connections=1,
                        latency_scope="client request through complete response body", quantile="nearest rank",
                        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        for protocol, interface in itertools.product(args.protocols, args.interfaces):
            common = [str(binary), "--protocol", protocol, "--interface", interface,
                      "--bytes", str(args.bytes), "--warmup", str(args.warmup),
                      "--address", address + ":0", "--timeout-seconds", str(args.timeout_seconds)]
            trust_identity = b""
            if protocol == "h3":
                common += ["--cert", native_path(cert, windows), "--key", native_path(key, windows),
                           "--ca", native_path(cert, windows)]
                trust_identity = hashlib.sha256(cert.read_bytes()).digest()

            def invoke(label, count, samples):
                invocation = common + ["--requests", str(count), "--samples", str(samples)]
                identity = hashlib.sha256(json.dumps(invocation).encode() + json.dumps(metadata, sort_keys=True).encode() + trust_identity).hexdigest()
                name = f"http-{backend}-{protocol}-{interface}-{label}"
                log = build / (name + ".log")
                prior = state.get(name, {})
                reuse = (prior.get("fingerprint") == identity and log.is_file() and
                         prior.get("log_sha256") == hashlib.sha256(log.read_bytes()).hexdigest())
                if not reuse:
                    print("MEASURE", name, "requests", count, "samples", samples, flush=True)
                    with log.open("w", encoding="utf-8") as destination:
                        completed = subprocess.run(invocation, cwd=root, env=environment, stdout=destination,
                                                   stderr=subprocess.STDOUT, timeout=args.timeout_seconds + 10, check=False)
                    if completed.returncode:
                        raise RuntimeError(f"HTTP process exited {completed.returncode}; see {log}")
                else:
                    print("REUSE", name, flush=True)
                clients = verify(log.read_text(encoding="utf-8"), backend, protocol, interface, count, samples, args.bytes)
                if not reuse:
                    prior = dict(fingerprint=identity, log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(), measured_at=time.time())
                    state[name] = prior
                    state_path.write_text(json.dumps(state, indent=2) + "\n")
                return clients, prior, log, reuse

            pilot, _, _, _ = invoke("calibration", args.requests, 1)
            count = max(args.requests, math.ceil(args.requests * args.seconds / pilot[0]["seconds"]))
            clients, evidence, log, reuse = invoke("samples", count, args.samples)
            for row in clients:
                rows.append(dict(row, **metadata, tls=protocol == "h3", measured_at=evidence["measured_at"],
                                 log=str(log), log_sha256=evidence["log_sha256"], reused=reuse,
                                 target_seconds=args.seconds))
            output.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows))
            print(f"{backend} {protocol} {interface}: "
                  f"{statistics.median(row['requests_per_second'] for row in clients):.1f} requests/s; "
                  f"p99 {statistics.median(row['latency_p99_ns'] for row in clients) / 1000:.1f} us", flush=True)
    print("Results:", output)


if __name__ == "__main__":
    main()
