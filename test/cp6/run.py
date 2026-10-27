import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checkpoint_common import Experiment, ROOT, packets, run


def main():
    exp = Experiment("cp6", sys.argv[1] if len(sys.argv) > 1 else "checkpoints/cp6")
    try:
        exp.create([1, 2, 3], [(1, 2), (1, 3)], "10.36")
        first = exp.capture(2, "out-a.pcap", "ip proto 253", exp.interfaces[2][0])
        second = exp.capture(3, "out-b.pcap", "ip proto 253", exp.interfaces[3][0])
        mac_a = run(["sudo", "-n", "./execNS", exp.ns(2), "cat",
                     "/sys/class/net/" + exp.interfaces[2][0] + "/address"], capture=True).strip()
        mac_b = run(["sudo", "-n", "./execNS", exp.ns(3), "cat",
                     "/sys/class/net/" + exp.interfaces[3][0] + "/address"], capture=True).strip()
        output = run(["sudo", "-n", "./execNS", exp.ns(1), ROOT / "tmp/cp6-lpm",
                      *exp.interfaces[1], mac_a, mac_b], capture=True)
        (exp.auxiliary / "lpm.txt").write_text(output)
        time.sleep(2)
        exp.stop_capture()
        a, b = packets(first), packets(second)
        assert {packet["payload"] for packet in a} == {"cp6-host", "cp6-network"}
        assert {packet["payload"] for packet in b} == {"cp6-subnet", "cp6-default"}
        assert len(a) == len(b) == 2
        expected = {
            "cp6-host": ("10.60.1.42", "10.36.1.1"),
            "cp6-subnet": ("10.60.1.43", "10.36.2.1"),
            "cp6-network": ("10.60.2.42", "10.36.1.1"),
            "cp6-default": ("203.0.113.7", "10.36.2.1")}
        for packet in a + b:
            dest, src = expected[packet["payload"]]
            assert (packet["dst"], packet["src"], packet["ttl"]) == (dest, src, 64)
        result = {"out_a": a, "out_b": b, "next_hop_a": mac_a, "next_hop_b": mac_b,
                  "source_sha256": exp.original_hashes}
        (exp.auxiliary / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print("CP6 PASS: /32, /24, /16 and /0; four checksum-valid packets on expected physical outlets", flush=True)
    finally:
        exp.close()


if __name__ == "__main__":
    main()
