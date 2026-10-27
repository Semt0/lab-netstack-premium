import hashlib
import os
from pathlib import Path
import re
import shlex
import signal
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "vnetUtils/helper"


def run(args, capture=False):
    args = [str(arg) for arg in args]
    print("$ " + shlex.join(args), flush=True)
    result = subprocess.run(args, cwd=HELPER, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    if capture:
        print(result.stdout, end="", flush=True)
        return result.stdout


def source_hashes():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((ROOT / "src").glob("*")) if p.is_file()}


def wait_for(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError("Timed out waiting for experiment result")


def packets(path):
    data = Path(path).read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[data[:4]]
    link_type = struct.unpack(endian + "I", data[20:24])[0]
    header_len = {1: 14, 113: 16, 276: 20}[link_type]
    offset = 24
    result = []
    while offset < len(data):
        sec, usec, size, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        frame = data[offset + 16:offset + 16 + size]
        assert len(frame) == size == original
        ip = frame[header_len:]
        assert ip[0] >> 4 == 4 and ip[9] == 253
        ihl = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        assert ihl >= 20 and ihl <= total <= len(ip)
        checksum = sum(int.from_bytes(ip[i:i + 2], "big") for i in range(0, ihl, 2))
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        assert checksum == 65535, "Bad IPv4 header checksum"
        result.append({"src": ".".join(map(str, ip[12:16])),
                       "dst": ".".join(map(str, ip[16:20])),
                       "ttl": ip[8], "payload": ip[ihl:total].decode(),
                       "timestamp": sec + usec / 1000000})
        offset += 16 + size
    return result


class Router:
    def __init__(self, namespace, interfaces, directory):
        self.path = directory / (namespace + ".typescript")
        assert not self.path.exists()
        command = ["sudo", "-n", "ip", "netns", "exec", namespace,
                   ROOT / "tmp/cp4-router", *interfaces]
        command = shlex.join([str(arg) for arg in command])
        print("$ script -q -f -e -c " + shlex.quote(command) + " " + str(self.path), flush=True)
        self.process = subprocess.Popen(
            ["script", "-q", "-f", "-e", "-c", command, str(self.path)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT, text=True, start_new_session=True)

    def text(self):
        return self.path.read_text(errors="replace") if self.path.exists() else ""

    def ready(self):
        return "Commands: route" in self.text()

    def write(self, command):
        assert self.process.poll() is None, self.text()[-2000:]
        print("> " + self.path.stem + ": " + command.rstrip(), flush=True)
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def routes(self, destinations):
        offset = len(self.path.read_bytes())
        self.write("\n".join("route " + ip for ip in destinations))
        pattern = re.compile(r"\[\d+\] (ROUTE|UNREACHABLE) dst=(\S+)([^\r\n]*)\r?\n")

        def read():
            results = {}
            for match in pattern.finditer(self.path.read_bytes()[offset:].decode(errors="replace")):
                kind, ip, fields = match.groups()
                results[ip] = None if kind == "UNREACHABLE" else dict(re.findall(r"(\w+)=(\S+)", fields))
            return results if len(results) == len(destinations) else None
        return wait_for(read)

    def send(self, destination, payload):
        offset = len(self.path.read_bytes())
        self.write("send " + destination + " " + payload)

        def read():
            text = self.path.read_bytes()[offset:].decode(errors="replace")
            if re.search(r"\[\d+\] UNREACHABLE dst=" + re.escape(destination) + r"\r?\n", text):
                return "UNREACHABLE"
            if "payload=" + payload + "\n" in text.replace("\r", ""):
                return "TX"
            return None
        return wait_for(read)

    def stop(self):
        if self.process.poll() is None:
            self.write("quit")
        code = self.process.wait(timeout=5)
        self.process.stdin.close()
        assert code == 0, (code, self.text()[-2000:])


class Experiment:
    def __init__(self, prefix, directory):
        self.prefix = prefix
        self.directory = ROOT / directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.auxiliary = ROOT / "tmp" / (prefix + "-aux-" + str(time.time_ns()))
        self.auxiliary.mkdir(parents=True)
        self.created = []
        self.interfaces = {}
        self.addresses = {}
        self.routers = {}
        self.captures = []
        self.original_hashes = source_hashes()

    def create(self, nodes, edges, subnet):
        existing = run(["sudo", "-n", "ip", "netns", "list"], capture=True)
        names = {line.split()[0] for line in existing.splitlines()}
        assert all(self.prefix + "ns" + str(i) not in names for i in nodes)
        for i in nodes:
            namespace = self.prefix + "ns" + str(i)
            run(["sudo", "-n", "./addNS", namespace])
            self.created.append(namespace)
            self.interfaces[i] = []
        for index, (a, b) in enumerate(edges, 1):
            first = self.prefix + "veth" + str(a) + "-" + str(b)
            second = self.prefix + "veth" + str(b) + "-" + str(a)
            network = subnet + "." + str(index)
            run(["sudo", "-n", "./connectNS", self.ns(a), self.ns(b), first, second, network])
            self.interfaces[a].append(first)
            self.interfaces[b].append(second)
            self.addresses.setdefault(a, network + ".1")
            self.addresses.setdefault(b, network + ".2")
        for i in nodes:
            run(["sudo", "-n", "./execNS", self.ns(i), "./bypassKernel"])
            run(["sudo", "-n", "./execNS", self.ns(i), "sysctl", "-w", "net.ipv4.ip_forward=0"])
            run(["sudo", "-n", "./execNS", self.ns(i), "ip", "-br", "addr"])
            run(["sudo", "-n", "./execNS", self.ns(i), "iptables", "-S"])

    def ns(self, i):
        return self.prefix + "ns" + str(i)

    def capture(self, i, filename, expression, interface="any"):
        path = self.directory / filename
        log = self.auxiliary / (filename + ".log")
        assert not path.exists() and not log.exists()
        stream = log.open("x")
        args = ["sudo", "-n", "ip", "netns", "exec", self.ns(i), "tcpdump",
                "-i", interface, "-Q", "in", "-nn", "-s0", "-U", "-w", str(path), expression]
        print("$ " + shlex.join(args), flush=True)
        process = subprocess.Popen(args, stdout=stream, stderr=stream, start_new_session=True)
        self.captures.append((process, stream, log))
        wait_for(lambda: "listening on" in log.read_text())
        return path

    def start_routers(self):
        for i, interfaces in self.interfaces.items():
            router = Router(self.ns(i), interfaces, self.directory)
            self.routers[i] = router
            wait_for(router.ready)

    def link(self, node, state):
        for interface in self.interfaces[node]:
            run(["sudo", "-n", "./execNS", self.ns(node), "ip", "link", "set", interface, state])
        run(["sudo", "-n", "./execNS", self.ns(node), "ip", "-br", "link"])

    def stop_capture(self):
        for process, stream, log in self.captures:
            if process.poll() is None:
                run(["sudo", "-n", "kill", "-INT", "--", "-" + str(process.pid)])
            code = process.wait(timeout=5)
            stream.close()
            print(str(log.name) + ": exit=" + str(code), flush=True)
            print(log.read_text(), flush=True)
            assert code in (0, 130, -signal.SIGINT), code
        self.captures.clear()

    def close(self):
        errors = []
        for router in self.routers.values():
            try:
                router.stop()
            except Exception as error:
                errors.append(str(error))
        try:
            self.stop_capture()
        except Exception as error:
            errors.append(str(error))
        for namespace in reversed(self.created):
            try:
                pids = run(["sudo", "-n", "ip", "netns", "pids", namespace], capture=True).split()
                if pids:
                    run(["sudo", "-n", "kill", "-TERM", *pids])
                    time.sleep(0.2)
                run(["sudo", "-n", "./delNS", namespace])
            except Exception as error:
                errors.append(str(error))
        assert source_hashes() == self.original_hashes, "src changed during experiment"
        assert not errors, errors
        print("Owned namespaces removed; src unchanged", flush=True)
