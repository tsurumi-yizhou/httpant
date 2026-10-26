#!/usr/bin/env python3
"""Build, validate, and measure the native backends in an existing build tree."""

import argparse
import hashlib
import itertools
import inspect
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("post", "timer", "tcp", "udp", "file")
TEST_PATTERN = "^(io$|execution$|quic$|http-h[123]-|io-bench-smoke$)"


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def executable(build, name, configuration):
    suffix = ".exe" if os.name == "nt" else ""
    for candidate in (build / configuration / (name + suffix), build / (name + suffix)):
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"executable not found: {name}")


def command(arguments, log, environment, timeout):
    print("+ " + subprocess.list2cmdline([str(argument) for argument in arguments]), flush=True)
    with log.open("w", encoding="utf-8") as output:
        try:
            result = subprocess.run(
                [str(argument) for argument in arguments], cwd=ROOT, env=environment,
                stdout=output, stderr=subprocess.STDOUT, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"command timed out; see {log}") from error
    if result.returncode:
        tail = "\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-12:])
        raise RuntimeError(f"command exited {result.returncode}; see {log}\n{tail}")


def fingerprint(build, configuration):
    digest = hashlib.sha256((platform.node() + platform.platform()).encode())
    paths = [executable(build, name, configuration) for name in (
        "io-test", "execution-test", "http-example", "io-bench")]
    if "HTTPANT_ENABLE_QUIC:BOOL=ON" in (build / "CMakeCache.txt").read_text(encoding="utf-8"):
        paths.append(executable(build, "quic-test", configuration))
    for path in paths:
        digest.update(str(path).encode())
        digest.update(path.read_bytes())
    # Hash effective tests, excluding CMake source line numbers and unrelated
    # cache entries. A documentation edit must not invalidate successful checks.
    try:
        listing = subprocess.check_output(
            ["ctest", "--test-dir", str(build), "-C", configuration,
             "--show-only=json-v1", "-R", TEST_PATTERN], text=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError("cannot inspect native CTest definitions") from error
    definitions = [dict(name=test["name"], command=test.get("command"),
                        properties=test.get("properties", []))
                   for test in json.loads(listing)["tests"]]
    if not definitions:
        raise RuntimeError("no native validation tests are registered")
    digest.update(json.dumps(definitions, sort_keys=True).encode())
    return digest.hexdigest()


def interoperate(server, client, protocol, interface, count, size, timeout, environment, log, address):
    common = ["--protocol", protocol, "--interface", interface, "--requests", str(count),
              "--bytes", str(size), "--timeout-seconds", str(timeout)]
    if protocol == "h3":
        common += ["--cert", str(server.parent / "quic-cert.pem"),
                   "--key", str(server.parent / "quic-key.pem"),
                   "--ca", str(server.parent / "quic-cert.pem")]
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen([str(server), "--mode", "server", "--address", f"{address}:0", *common], cwd=ROOT,
                                   env=environment, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + timeout
            while True:
                text = log.read_text(encoding="utf-8", errors="replace")
                marker = "server listening on port "
                if marker in text:
                    port = int(text.split(marker, 1)[1].split()[0])
                    break
                if process.poll() is not None:
                    raise RuntimeError(f"example server exited {process.returncode} before listening; see {log}")
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"example server did not become ready; see {log}")
                time.sleep(0.01)
            result = subprocess.run([str(client), "--mode", "client", "--address", f"{address}:{port}", *common], cwd=ROOT,
                                    env=environment, stdout=output, stderr=subprocess.STDOUT,
                                    timeout=timeout + 5, check=False)
            if result.returncode or process.wait(timeout=timeout + 5):
                raise RuntimeError(f"HTTP backend interoperability failed; see {log}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
               if line.startswith("{")]
    if len(records) != 2 or any(row.get("verified") is not True for row in records):
        raise RuntimeError(f"both HTTP endpoints must verify their exchange; see {log}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/debug")
    parser.add_argument("--data-dir", type=Path, help="existing directory for temporary I/O files; defaults to the build directory")
    parser.add_argument("--preset", help="optional local configure preset; --build-dir still selects the existing build tree")
    parser.add_argument("--backends", nargs="+", help="defaults to the mechanisms for this host OS")
    parser.add_argument("--address", default="127.0.0.2" if platform.system() == "Linux" else "127.0.0.1",
                        help="local IPv4 address for both network endpoints; Linux routes must use lo")
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument("--concurrency", type=positive, nargs="+", default=[1])
    parser.add_argument("--bytes", type=positive, nargs="+", default=[1024])
    parser.add_argument("--iterations", type=positive, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--samples", type=positive, default=3)
    parser.add_argument("--seconds", type=float, default=0, help="target duration of each I/O sample; zero uses the iteration count")
    parser.add_argument("--http-warmup", type=int, default=0)
    parser.add_argument("--http-samples", type=positive, default=1)
    parser.add_argument("--timer-us", type=positive, default=1000)
    parser.add_argument("--http-requests", type=positive, default=100)
    parser.add_argument("--interop", action="store_true", help="also check every built server/client backend pair in separate processes")
    parser.add_argument("--check-only", action="store_true", help="build and validate without performance samples")
    parser.add_argument("--protocols", nargs="+", choices=("h1", "h2", "h3"), default=["h1", "h2", "h3"])
    parser.add_argument("--interfaces", nargs="+", choices=("coroutine", "execution"), default=["coroutine", "execution"])
    parser.add_argument("--configuration", choices=("Release", "RelWithDebInfo"), default="Release")
    parser.add_argument("--jobs", type=positive, default=2)
    parser.add_argument("--timeout-seconds", type=positive, default=60)
    parser.add_argument("--output", type=Path, help="JSONL results file, default: BUILD_DIR/native-results.jsonl")
    arguments = parser.parse_args()
    try:
        address = str(ipaddress.IPv4Address(arguments.address))
    except ipaddress.AddressValueError as error:
        parser.error(str(error))
    if not ipaddress.IPv4Address(address).is_loopback:
        parser.error("--address must be a loopback IPv4 address")
    if platform.system() == "Linux":
        for protocol in ("tcp", "udp"):
            route = json.loads(subprocess.check_output(
                ["ip", "-j", "route", "get", address, "ipproto", protocol], text=True))
            if not route or route[0].get("dev") != "lo":
                parser.error(f"{protocol} route to {address} must use lo")
    build = arguments.build_dir.resolve()
    if not build.is_dir() or not (build / "CMakeCache.txt").is_file():
        parser.error("--build-dir must be an existing configured project build directory")
    directory = arguments.data_dir.resolve() if arguments.data_dir else build
    if not directory.is_dir():
        parser.error("--data-dir must be an existing directory")
    if os.name == "nt" and (len(directory.drive) != 2 or directory.drive[1] != ':'):
        parser.error("Windows I/O data must use a local drive directory")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    source = next((line.split("=", 1)[1] for line in cache.splitlines()
                   if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")), "")
    if Path(source).resolve() != ROOT:
        parser.error("the build directory belongs to another project")
    if arguments.seconds < 0 or not math.isfinite(arguments.seconds):
        parser.error("--seconds must be finite and nonnegative")
    if arguments.http_warmup < 0:
        parser.error("--http-warmup cannot be negative")
    if arguments.warmup < 0:
        parser.error("--warmup cannot be negative")
    supported = {"Linux": ("asio", "uring", "epoll"), "Windows": ("asio", "ioring", "iocp"),
                 "Darwin": ("asio", "kqueue"), "FreeBSD": ("asio", "kqueue"), "OpenBSD": ("asio", "kqueue"),
                 "NetBSD": ("asio", "kqueue"), "DragonFly": ("asio", "kqueue")}.get(platform.system(), ("asio",))
    backends = arguments.backends or list(supported)
    if not backends or any(backend not in supported for backend in backends):
        parser.error(f"choose backends for {platform.system()}: {', '.join(supported)}")
    if len(set(backends)) != len(backends):
        parser.error("duplicate backend names would repeat identical checks")
    output = arguments.output.resolve() if arguments.output else build / "native-results.jsonl"
    if not output.parent.is_dir():
        parser.error("the results directory must already exist")
    environment = os.environ.copy()
    environment["TMPDIR"] = str(build)
    if os.name == "nt":
        environment["TEMP"] = environment["TMP"] = str(build)
    state_path = build / "native-validation-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    rows, failures, built = [], [], {}
    with output.open("w", encoding="utf-8") as destination:
        def save(row):
            if platform.system() == "Linux" and (row.get("record") in ("application", "interoperability") or row.get("scenario") in ("tcp", "udp")):
                row["device"] = "lo"
            row.update(host=platform.node(), os=platform.platform(), machine=platform.machine(),
                       processor=platform.processor(), recorded_at=time.time())
            destination.write(json.dumps(row, ensure_ascii=True) + "\n")
            destination.flush()
            rows.append(row)

        def failure(backend, error, **conditions):
            message = str(error)
            failures.append(backend)
            save(dict(record="failure", configured_backend=backend, error=message, **conditions))
            print(f"{backend}: {message}", file=sys.stderr, flush=True)

        def measurement(backend, kind, invocation, log, timeout, expected, **conditions):
            try:
                command(invocation, log, environment, timeout)
                records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
                if len(records) != expected:
                    raise RuntimeError("measurement did not emit the requested number of records")
                if any(row.get("address") != address for row in records):
                    raise RuntimeError("measurement address differs from --address")
                if kind == "application" and any(row.get("verified") is not True for row in records):
                    raise RuntimeError("HTTP example did not verify both endpoint roles")
                for row in records:
                    save(dict(row, record=kind, configured_backend=backend))
            except (OSError, RuntimeError, ValueError) as error:
                failure(backend, error, measurement=kind, **conditions)

        for backend in backends:
            try:
                configure = ["cmake"]
                if arguments.preset:
                    configure += ["--preset", arguments.preset]
                configure += ["-S", ROOT, "-B", build,
                              f"-DCMAKE_BUILD_TYPE={arguments.configuration}",
                              "-DHTTPANT_ENABLE_IO=ON", f"-DHTTPANT_IO_BACKEND={backend}",
                              "-DBUILD_BENCHMARKS=ON", "-DBUILD_EXAMPLES=ON",
                              "-DHTTPANT_ENABLE_QUIC=" + ("ON" if "h3" in arguments.protocols else "OFF"),
                              "-DBUILD_TESTING=ON", f"-DHTTPANT_DATA_DIR={directory}"]
                command(configure, build / f"{backend}-native-configure.log", environment, 1200)
                targets = ["io-bench", "http-example", "io-test", "execution-test"]
                if "h3" in arguments.protocols:
                    targets.append("quic-test")
                command(["cmake", "--build", build, "--config", arguments.configuration,
                         "--parallel", arguments.jobs, "--target", *targets],
                        build / f"{backend}-native-build.log", environment, 1200)
                identity = fingerprint(build, arguments.configuration)
                evidence = state.get(backend, {})
                test_log = build / f"{backend}-native-check.log"
                if evidence.get("fingerprint") == identity and test_log.is_file() and \
                        hashlib.sha256(test_log.read_bytes()).hexdigest() == evidence.get("log_sha256"):
                    print(f"Reusing successful {backend} validation: {test_log}", flush=True)
                else:
                    command(["ctest", "--test-dir", build, "-C", arguments.configuration,
                             "--output-on-failure", "--no-tests=error", "-R",
                             TEST_PATTERN],
                            test_log, environment, 300)
                    state[backend] = {"fingerprint": identity,
                                      "log_sha256": hashlib.sha256(test_log.read_bytes()).hexdigest()}
                    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                save({"record": "validation", "configured_backend": backend, "status": "passed",
                      "fingerprint": identity, "log": str(test_log)})
                bench = executable(build, "io-bench", arguments.configuration)
                example = executable(build, "http-example", arguments.configuration)
                retained = {}
                for label, binary in (("benchmark", bench), ("example", example)):
                    copy = build / (binary.stem + "-" + backend + binary.suffix)
                    if not copy.exists() or copy.read_bytes() != binary.read_bytes():
                        shutil.copy2(binary, copy)
                    retained[label] = copy
                built[backend] = retained
                if arguments.check_only:
                    continue
                for scenario, concurrency in itertools.product(arguments.scenarios, arguments.concurrency):
                    sizes = arguments.bytes if scenario not in ("post", "timer") else arguments.bytes[:1]
                    for size in sizes:
                        log = build / f"{backend}-native-{scenario}-{concurrency}-{size}.log"
                        measurement(backend, "benchmark", [bench, "--directory", directory, "--scenario", scenario, "--address", address,
                                 "--concurrency", concurrency, "--bytes", size,
                                 "--iterations", arguments.iterations, "--warmup", arguments.warmup,
                                 "--samples", arguments.samples, "--timer-us", arguments.timer_us,
                                 "--timeout-seconds", arguments.timeout_seconds,
                                 *(["--seconds", arguments.seconds] if arguments.seconds else [])], log,
                                arguments.timeout_seconds * (2 * arguments.samples + 1) + 10,
                                arguments.samples, scenario=scenario, concurrency=concurrency, payload_bytes=size)
                for protocol, interface in itertools.product(arguments.protocols, arguments.interfaces):
                    for size in arguments.bytes:
                        log = build / f"{backend}-native-http-{protocol}-{interface}-{size}.log"
                        measurement(backend, "application", [example, "--protocol", protocol, "--interface", interface, "--address", f"{address}:0",
                                 "--requests", arguments.http_requests, "--bytes", size,
                                 "--warmup", arguments.http_warmup, "--samples", arguments.http_samples,
                                 "--timeout-seconds", arguments.timeout_seconds,
                                 *(["--cert", build / "quic-cert.pem", "--key", build / "quic-key.pem",
                                    "--ca", build / "quic-cert.pem"] if protocol == "h3" else [])],
                                log, arguments.timeout_seconds + 10, 2 * arguments.http_samples,
                                protocol=protocol, interface=interface, payload_bytes=size)
            except (OSError, RuntimeError, ValueError) as error:
                failure(backend, error, measurement="build-or-validation")

        if arguments.interop:
            evidence = state.setdefault("interoperability", {})
            for server, client, protocol, interface in itertools.product(
                    built, built, arguments.protocols, arguments.interfaces):
                size = arguments.bytes[0]
                key = f"{address}-{server}-{client}-{protocol}-{interface}-{size}-{arguments.http_requests}"
                log = build / ("native-interop-" + key + ".log")
                binaries = built[server]["example"], built[client]["example"]
                identity = hashlib.sha256(
                    platform.platform().encode() + key.encode() +
                    str(arguments.timeout_seconds).encode() + inspect.getsource(interoperate).encode() +
                    b"".join(hashlib.sha256(binary.read_bytes()).digest() for binary in binaries)
                ).hexdigest()
                prior = evidence.get(key, {})
                try:
                    if prior.get("fingerprint") == identity and log.is_file() and \
                            prior.get("log_sha256") == hashlib.sha256(log.read_bytes()).hexdigest():
                        print(f"Reusing successful HTTP backend pair: {key}", flush=True)
                    else:
                        print(f"Checking HTTP server={server} client={client} {protocol} {interface}", flush=True)
                        interoperate(*binaries, protocol, interface, arguments.http_requests, size,
                                     arguments.timeout_seconds, environment, log, address)
                        evidence[key] = {"fingerprint": identity,
                                         "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
                        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                    save(dict(record="interoperability", server_backend=server, client_backend=client,
                              protocol=protocol, interface=interface, payload_bytes=size,
                              requests=arguments.http_requests, address=address, status="passed", log=str(log)))
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                    failure(f"{server}->{client}", error, measurement="interoperability",
                            protocol=protocol, interface=interface, payload_bytes=size)

    groups = {}
    for row in rows:
        if row["record"] == "benchmark":
            key = row["configured_backend"], row["scenario"], row["concurrency"], row["payload_bytes"]
            groups.setdefault(key, []).append(row)
    print("\nbackend scenario concurrency bytes median_ops/s median_p99_us")
    for (backend, scenario, concurrency, size), samples in groups.items():
        throughput = statistics.median(row["operations_per_second"] for row in samples)
        latency = statistics.median(row["latency_p99_ns"] for row in samples) / 1000
        print(f"{backend:8} {scenario:8} {concurrency:11} {size:5} {throughput:12.1f} {latency:13.2f}")
    print(f"\nResults: {output}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
