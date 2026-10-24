# CS 352 Project 2 — Domain Name System

A DNS client built from raw UDP sockets, with no DNS libraries. Queries are
assembled byte by byte and responses are parsed by hand, including name
compression pointers.

## Group Members

| Name | netID |
|---|---|
| Nathaniel Sherwood | nps104 |
| Aidan Dipasupal | akd142 |

## What Each Part Does

| Part | Program | Behavior |
|---|---|---|
| A | `Project2_PartA_skeleton.py` | Recursive resolver. Sends A and AAAA queries to 8.8.8.8 with RD=1 and extracts the addresses from the answer section. |
| B | `Project2_PartB_skeleton.py` | NS records. Queries for NS records and parses the Authority and Additional sections in addition to Answer. |
| C | `Project2_PartC_skeleton.py` | Iterative resolver. Sends RD=0 and walks the delegation chain from a root server down to the authoritative server, following glue records at each step. |

## Files

| File | Contents |
|---|---|
| `Project2_PartA_skeleton.py` | Part A implementation |
| `Project2_PartB_skeleton.py` | Part B implementation |
| `Project2_PartC_skeleton.py` | Part C implementation |
| `project2_partA.pcap` | Capture: 4 query/response pairs with 8.8.8.8 |
| `project2_partB.pcap` | Capture: NS query for princeton.edu |
| `project2_partC.pcap` | Capture: 3-hop iterative walk (frames 1-6 are ours) |
| `Input.json` | Test input read by Part A |
| `output.txt` | Part A output |
| `REPORT.md` | **The report** — answers to all 15 Wireshark questions |
| `root-servers` | Root server IP list (provided) |

## Running

Part A reads its queries from a file. It accepts either `input.txt` (the
format shown in the project description, an object with a `questions` key)
or `Input.json` (a bare JSON array), and handles both shapes.

```bash
python3 Project2_PartA_skeleton.py     # writes output.txt
python3 Project2_PartB_skeleton.py
python3 Project2_PartC_skeleton.py
```

Part C needs to reach the root servers over UDP/53 directly. Networks that
force all DNS through a local resolver will block it.

## How the Captures Were Made

On rlab5, with the capture started before the program and stopped after it.
Running both in a single shell matters: two separate SSH sessions can land
on different hosts, in which case tshark watches one machine while the
program runs on another.

```bash
tshark -i any -f "udp port 53" -F pcap -w project2_partA.pcap &
TSHARK_PID=$!
sleep 3
python3 Project2_PartA_skeleton.py
sleep 2
kill -INT $TSHARK_PID
wait $TSHARK_PID
```

The `sleep 3` gives tshark time to attach to the interface — anything sent
before that is lost. `-F pcap` forces classic pcap format, since tshark
writes pcapng by default.

Because rlab5 is shared and `-i any` captures everything, the Part C file
contains unrelated background DNS traffic from the machine's own resolver.
Our three exchanges are frames 1-6; see the open items in `REPORT.md`.

To view only our Part C traffic in Wireshark:

```
ip.addr==198.41.0.4 || ip.addr==192.31.80.30 || ip.addr==130.156.133.30
```

## Implementation Notes

**Name compression.** `parse_name` follows pointers (a length byte whose top
two bits are `11`) but returns two values: the decoded name, and the offset
the caller should resume from. Those differ whenever a pointer is followed,
because the caller must continue past the 2-byte pointer rather than past
wherever the jump landed.

**Record sizes.** `parse_rr` always advances by RDLENGTH, never by the
length of what it decoded. A compressed NS name may decode to 20 characters
while occupying 4 bytes on the wire.

**Truncation.** Parts A and B exit with an error on TC=1, per the project
description. Part C does not, because every root referral is truncated — it
continues as long as the glue it needs survived. This is discussed under
Q11 in the report.

**Glue.** Part C matches NS hostnames from the Authority section against A
records in the Additional section. The project description says to assume
glue is always available and error otherwise, which is what happens. Note
that `www.princeton.edu` cannot be resolved iteratively under that
assumption: Princeton's nameservers are outside `.edu`, so `.edu` returns
ARCOUNT=0 and there is no glue to follow.

## Report

See [REPORT.md](REPORT.md). Open items that still need attention are listed
at the top of that file, before the answers.
