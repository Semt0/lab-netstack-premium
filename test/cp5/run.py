import csv
from collections import Counter, deque
import json
from pathlib import Path
import sys
import struct
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checkpoint_common import Experiment, packets, wait_for

NODES = list(range(1, 7))
EDGES = [(1, 2), (2, 3), (3, 4), (2, 5), (3, 6), (5, 6)]


def expected_matrix(edges):
    adjacency = {i: [] for i in NODES}
    for a, b in edges:
        adjacency[a].append(b)
        adjacency[b].append(a)
    result = []
    for source in NODES:
        distances = {source: 0}
        queue = deque([source])
        while queue:
            node = queue.popleft()
            for neighbor in adjacency[node]:
                if neighbor not in distances:
                    distances[neighbor] = distances[node] + 1
                    queue.append(neighbor)
        result.append([distances.get(i) for i in NODES])
    return result


def matrix(exp, phase, edges):
    expected = expected_matrix(edges)
    destinations = [exp.addresses[i] for i in NODES]
    deadline = time.monotonic() + 90
    stable = 0
    started = time.monotonic()
    while time.monotonic() < deadline:
        records = [exp.routers[i].routes(destinations) for i in NODES]
        actual = [[None if row[ip] is None else int(row[ip]["metric"])
                   for ip in destinations] for row in records]
        mismatches = sum(a != b for row, expected_row in zip(actual, expected)
                         for a, b in zip(row, expected_row))
        print(phase + ": mismatches=" + str(mismatches), flush=True)
        stable = stable + 1 if mismatches == 0 else 0
        if stable == 3:
            for source, row in enumerate(records, 1):
                for dest, ip in zip(NODES, destinations):
                    entry = row[ip]
                    if entry is not None:
                        assert int(entry["learned_from_dv"]) == int(source != dest)
            result = {"phase": phase, "targets": exp.addresses, "actual": actual,
                      "expected": expected, "route_records": records,
                      "observation_seconds": round(time.monotonic() - started, 3)}
            (exp.auxiliary / (phase + ".json")).write_text(json.dumps(result, indent=2) + "\n")
            with (exp.auxiliary / (phase + ".csv")).open("x", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["source/destination"] + ["ns" + str(i) for i in NODES])
                for i, row in zip(NODES, actual):
                    writer.writerow(["ns" + str(i)] + ["INF" if x is None else x for x in row])
            print(phase + " actual distance matrix:", flush=True)
            print((exp.auxiliary / (phase + ".csv")).read_text(), flush=True)
            return actual
        time.sleep(1)
    (exp.auxiliary / (phase + "-failed.json")).write_text(
        json.dumps({"actual": actual, "expected": expected, "records": records}, indent=2))
    raise RuntimeError(phase + ": distance matrix failed to converge")


def probe(exp, phase, distances):
    expected = {}
    blocked = 0
    for source in NODES:
        for destination in NODES:
            if source == destination:
                continue
            payload = "cp5-" + phase + "-" + str(source) + "-" + str(destination)
            status = exp.routers[source].send(exp.addresses[destination], payload)
            distance = distances[source - 1][destination - 1]
            if distance is None:
                assert status == "UNREACHABLE"
                blocked += 1
            else:
                assert status == "TX"
                expected[payload] = {"destination": destination,
                                     "ip": exp.addresses[destination], "ttl": 65 - distance}
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        received = {}
        for payload, check in expected.items():
            text = exp.routers[check["destination"]].text()
            lines = [line for line in text.splitlines()
                     if "] RX " in line and line.endswith("payload=" + payload)]
            if lines:
                assert len(lines) == 1, (payload, lines)
                assert "dst=" + check["ip"] + " " in lines[0], lines[0]
                assert "ttl=" + str(check["ttl"]) + " " in lines[0], lines[0]
                received[payload] = lines[0]
        if len(received) == len(expected):
            print(phase + ": delivered=" + str(len(received)) + " blocked=" + str(blocked), flush=True)
            return {"delivered": len(received), "blocked": blocked,
                    "expected": expected, "received": received}
        time.sleep(0.1)
    raise RuntimeError("Missing deliveries: " + str(sorted(set(expected) - set(received))))


def main():
    exp = Experiment("cp5", sys.argv[1] if len(sys.argv) > 1 else "checkpoints/cp5")
    results = {}
    try:
        exp.create(NODES, EDGES, "10.35")
        capture_paths = {}
        for i in NODES:
            capture_paths[i] = exp.capture(
                i, "ns" + str(i) + ".pcap",
                "ip proto 253 and dst host " + exp.addresses[i])
        exp.start_routers()
        distances = matrix(exp, "before", EDGES)
        results["before"] = probe(exp, "before", distances)

        print("ISOLATE ns5: both interfaces down; all processes remain running", flush=True)
        exp.link(5, "down")
        cut_edges = [edge for edge in EDGES if 5 not in edge]
        distances = matrix(exp, "isolated", cut_edges)
        results["isolated"] = probe(exp, "isolated", distances)

        print("RESTORE ns5: both interfaces up; no process restart", flush=True)
        exp.link(5, "up")
        distances = matrix(exp, "restored", EDGES)
        results["restored"] = probe(exp, "restored", distances)

        expected = {payload: check for result in results.values()
                    for payload, check in result["expected"].items()}

        # 接收回调与 tcpdump 的缓冲独立，等抓包文件收齐后再停止。
        def capture_complete():
            try:
                captured = [packet for path in capture_paths.values() for packet in packets(path)]
            except (AssertionError, KeyError, struct.error):
                return None
            return captured if len(captured) >= len(expected) else None

        wait_for(capture_complete, timeout=12)
        exp.stop_capture()
        captured = [packet for path in capture_paths.values() for packet in packets(path)]
        counts = Counter(packet["payload"] for packet in captured)
        assert counts == Counter({payload: 1 for payload in expected}), counts
        for packet in captured:
            check = expected[packet["payload"]]
            assert packet["dst"] == check["ip"] and packet["ttl"] == check["ttl"]
        results["captured_datagrams"] = len(captured)
        results["source_sha256"] = exp.original_hashes
        (exp.auxiliary / "result.json").write_text(json.dumps(results, indent=2) + "\n")
        print("CP5 PASS: three 6x6 matrices, 80 deliveries, 10 unreachable sends, 80 checksum-valid packets", flush=True)
    finally:
        exp.close()


if __name__ == "__main__":
    main()
