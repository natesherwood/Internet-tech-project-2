# CS 352 Project 2 — Domain Name System
## Report

### GROUP MEMBERS

| Name | netID |
|---|---|
| [NAME] | [NETID] |
| [NAME] | [NETID] |

---

# ⚠️ OPEN ITEMS — READ FIRST, RESOLVE BEFORE SUBMITTING

## 1. Names and netIDs — REQUIRED

Deliverable 4 says the report must list the name and netID of every group
member. Fill in the table above. This is the only item that cannot be
resolved from the captures.

## 2. whale.stanford.edu query type — ASK THE TA

There is a conflict between the two sources:

- `Input.json` (the file provided to us) lists `whale.stanford.edu` with
  **qtype 28 (AAAA)**
- The project description, pages 4–5, shows `whale.stanford.edu` with
  **qtype 1 (A)**

This was tested directly against 8.8.8.8:

```
whale.stanford.edu  A     -> ANCOUNT=1  171.64.75.72
whale.stanford.edu  AAAA  -> ANCOUNT=0  (no record; SOA returned instead)
```

So the host **has an A record and has no AAAA record.** Because our input
asks for AAAA, the response carries no address, which is why questions 2, 3
and 4 below have no row for whale.

**If the official test file uses qtype 1:** change `Input.json` and
**recapture Part A**. Every other Part A answer stays the same.

## 3. Transaction ID — DECISION NEEDED

The project description contradicts itself:

- Page 2: *"You should always use 1337 for this field."*
- The starter code on page 4 uses `random.randint(0, 65535)`

The three programs are currently inconsistent with each other:

| Program | ID used now | ID in the submitted capture |
|---|---|---|
| Part A | `random.randint(0, 65535)` | `0x0ed9`, `0x077c`, `0x3ec4`, `0x4546` |
| Part B | **`1337` (`0x0539`)** | `0x1475` — capture predates this change |
| Part C | `random.randint(0, 65535)` | `0x93b8` (reused for all three hops) |

**Part B's code was changed to use 1337 after `project2_partB.pcap` was
captured**, so the program and the capture no longer agree. Part B's code
also now queries a second domain, `example.com`, which is not in the
assignment's test suite — rerunning it produces four packets rather than
the two in the submitted capture.

**To make everything consistent, pick one:**

- Set `"id"` to `1337` in Parts A and C as well, set Part B's `DOMAINS`
  back to `["princeton.edu"]` only, and recapture all three pcaps. The
  transaction IDs in this report then all become `0x0539`, and nothing
  else changes.
- Or revert Part B to a random ID and a single domain, matching the
  submitted capture and the rest of the code.

Everything else in this report describes the submitted captures and is
unaffected either way.

## 4. Extra traffic in the Part C capture — explained, no action needed

`project2_partC.pcap` contains 16 packets, but only **frames 1–6** are ours.
Frames 7–16 are unrelated `victoria.cs.rutgers.edu` lookups performed by
rlab5's own system resolver (127.0.0.53 and 172.16.x.x), captured because
`-i any` sees all traffic on a shared machine.

Question 12 refers to "the three responses" — those are **frames 2, 4 and 6**.

To isolate our traffic in Wireshark, use this display filter:

```
ip.addr==198.41.0.4 || ip.addr==192.31.80.30 || ip.addr==130.156.133.30
```

---

# FILES SUBMITTED

| File | Contents |
|---|---|
| `Project2_PartA_skeleton.py` | Recursive resolver, A and AAAA records |
| `Project2_PartB_skeleton.py` | NS record support |
| `Project2_PartC_skeleton.py` | Iterative resolver |
| `project2_partA.pcap` | 8 packets — 4 query/response pairs with 8.8.8.8 |
| `project2_partB.pcap` | 2 packets — NS query for princeton.edu |
| `project2_partC.pcap` | 16 packets — our 3 hops are frames 1–6 |
| `Input.json` | Test input; Part A reads this |
| `REPORT.md` | This file |

All hexadecimal values below were read from the submitted captures.

---

# PART A — Recursive Resolver

## Wireshark Activity

**Transaction ID** — one per query, echoed in the matching response:

| Frames | Query | Transaction ID |
|---|---|---|
| 1, 2 | ilab1.cs.rutgers.edu A | `0x0ed9` |
| 3, 4 | ilab1.cs.rutgers.edu AAAA | `0x077c` |
| 5, 6 | whale.stanford.edu AAAA | `0x3ec4` |
| 7, 8 | www.princeton.edu A | `0x4546` |

**Flags**

| Direction | Flags | Meaning |
|---|---|---|
| Query | `0x0100` | QR=0 (query), OPCODE=0, RD=1 (recursion desired) |
| Response | `0x8180` | QR=1 (response), RD=1, RA=1 (recursion available), RCODE=0 |

**Question section** — QNAME, QTYPE=`0x0001` (A) or `0x001c` (AAAA),
QCLASS=`0x0001` (IN). See Q1 for the QNAME bytes.

**Answer section** — see Q2 through Q4.

## Q1. Domain name in the question section of the DNS query (hex)

| Query | QNAME bytes |
|---|---|
| `ilab1.cs.rutgers.edu` | `05 69 6c 61 62 31 02 63 73 07 72 75 74 67 65 72 73 03 65 64 75 00` |
| `whale.stanford.edu` | `05 77 68 61 6c 65 08 73 74 61 6e 66 6f 72 64 03 65 64 75 00` |
| `www.princeton.edu` | `03 77 77 77 09 70 72 69 6e 63 65 74 6f 6e 03 65 64 75 00` |

A domain name is transmitted as a sequence of labels. Each label is one
length byte followed by that many ASCII characters. The name ends with the
zero byte `00`, the null label of the root. Dots are never sent — they are
implied by the label boundaries.

Reading the first one: `05` then `ilab1`, `02` then `cs`, `07` then
`rutgers`, `03` then `edu`, then `00`.

## Q2. Domain name in the answer section of the DNS response (hex) — explain

```
c0 0c
```

The answer's NAME field is **not** the name written out. It is a two-byte
**compression pointer**.

A length byte whose top two bits are `11` marks a pointer rather than a
label. `0xc00c` is `1100 0000 0000 1100` — strip the two flag bits and the
remaining 14 bits give the value `0x00c` = **12**, a byte offset from the
start of the DNS message. Offset 12 is exactly where the question section
begins, immediately after the 12-byte header.

So instead of repeating the 22 bytes of `ilab1.cs.rutgers.edu`, the server
stores 2 bytes pointing back at the copy already in the question section.
This is DNS name compression, and it is why RDLENGTH values vary (see Q9).

A second form appears in frame 8. Answers #2 and #3 use `c0 2f`, which
points to offset 47 — inside the CNAME record's RDATA, where
`www.princeton.edu.cdn.cloudflare.net` was written out in full.

## Q3. RDLENGTH field in the DNS response (hex)

| Frame | Query | Record | RDLENGTH | Decimal |
|---|---|---|---|---|
| 2 | ilab1.cs.rutgers.edu A | A | `00 04` | 4 bytes (IPv4) |
| 4 | ilab1.cs.rutgers.edu AAAA | AAAA | `00 10` | 16 bytes (IPv6) |
| 6 | whale.stanford.edu AAAA | SOA (authority) | `00 29` | 41 bytes |
| 8 | www.princeton.edu A | CNAME | `00 26` | 38 bytes |
| 8 | www.princeton.edu A | A | `00 04` | 4 bytes |
| 8 | www.princeton.edu A | A | `00 04` | 4 bytes |

RDLENGTH is fixed by record type for addresses — always 4 for A and 16 for
AAAA — but varies for name-bearing records such as CNAME, NS and SOA.

## Q4. Address received in the DNS response (hex)

| Query | Address | Hex bytes |
|---|---|---|
| ilab1.cs.rutgers.edu A | `128.6.13.2` | `80 06 0d 02` |
| ilab1.cs.rutgers.edu AAAA | `2620:0:d60:ac0d::2` | `26 20 00 00 0d 60 ac 0d 00 00 00 00 00 00 00 02` |
| www.princeton.edu A | `104.18.4.101` | `68 12 04 65` |
| www.princeton.edu A | `104.18.5.101` | `68 12 05 65` |

An A record's RDATA is the four address octets in order. An AAAA record's
RDATA is the sixteen bytes of the IPv6 address, with the `::` shorthand
expanded to explicit zero bytes.

**whale.stanford.edu returns no address.** Frame 6 has ANCOUNT = `00 00`
and NSCOUNT = `00 01`; the server answers with an SOA record in the
Authority section instead. The query succeeded (RCODE = 0) — the host
simply has no AAAA record. See open item 2.

## Q5. Why is ANCOUNT for www.princeton.edu 3, but only 2 IP addresses returned?

Frame 8 has ANCOUNT = `00 03`, but the three answer records are not three
addresses:

| # | TYPE | Record | Value |
|---|---|---|---|
| 1 | `00 05` | CNAME | www.princeton.edu → www.princeton.edu.cdn.cloudflare.net |
| 2 | `00 01` | A | 104.18.4.101 |
| 3 | `00 01` | A | 104.18.5.101 |

The first record is a **CNAME** — a canonical-name alias. It carries a
domain name, not an address, and says "the name you asked about is really
this other name." Princeton serves its site through Cloudflare, so the
actual A records belong to the Cloudflare hostname rather than to
`www.princeton.edu` directly.

Only TYPE `0x0001` (A) and TYPE `0x001c` (AAAA) records contain addresses.
Three answer records therefore yield two IP addresses. Our resolver skips
any answer record whose type is not an address type, which is why its
output lists exactly the two Cloudflare addresses.

---

# PART B — NS Records

Query: `princeton.edu`, QTYPE = `00 02` (NS), RD = 1, sent to 8.8.8.8.

## Wireshark Activity

**Authority and Additional sections:** both are **empty** in this response —
NSCOUNT = `00 00` and ARCOUNT = `00 00`. All nine NS records are in the
Answer section (see Q10).

**Matching NS hostnames with glue A records:** the activity says to do this
"if present." Here there are **no glue records at all**, because ARCOUNT is
zero. A recursive resolver answering a direct NS question has no reason to
supply glue — glue exists to make a *referral* usable, and this is an
answer, not a referral. Glue matching is demonstrated in Part C instead,
where it is essential (see Q15).

## Q6. QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT in the response (hex)

```
QDCOUNT = 00 01      1 question
ANCOUNT = 00 09      9 answer records
NSCOUNT = 00 00      0 authority records
ARCOUNT = 00 00      0 additional records
```

## Q7 and Q8. RDLENGTH and name server name for each resource record

All nine records are TYPE `00 02` (NS) and CLASS `00 01` (IN).

| # | Name server | RDLENGTH | RDATA (hex) |
|---|---|---|---|
| 1 | a20-65.akam.net | `00 11` | `06 61 32 30 2d 36 35 04 61 6b 61 6d 03 6e 65 74 00` |
| 2 | a24-66.akam.net | `00 09` | `06 61 32 34 2d 36 36 c0 32` |
| 3 | a1-158.akam.net | `00 09` | `06 61 31 2d 31 35 38 c0 32` |
| 4 | a7-65.akam.net | `00 08` | `05 61 37 2d 36 35 c0 32` |
| 5 | ns6.dnsmadeeasy.com | `00 15` | `03 6e 73 36 0b 64 6e 73 6d 61 64 65 65 61 73 79 03 63 6f 6d 00` |
| 6 | a6-64.akam.net | `00 08` | `05 61 36 2d 36 34 c0 32` |
| 7 | ns7.dnsmadeeasy.com | `00 06` | `03 6e 73 37 c0 8a` |
| 8 | a3-67.akam.net | `00 08` | `05 61 33 2d 36 37 c0 32` |
| 9 | ns5.dnsmadeeasy.com | `00 06` | `03 6e 73 35 c0 8a` |

## Q9. Why are the RDLENGTH values of the NS records not all the same?

An NS record's RDATA **is a domain name**, stored in the same label format
as a QNAME. Its size therefore depends entirely on the name, and two
separate effects make the names different sizes.

**1. The hostnames themselves differ in length.** Compare records 2 and 4:
`a24-66` is six characters and `a7-65` is five, so their RDLENGTHs are
`00 09` and `00 08`.

**2. Name compression.** This is the larger effect. Record 1 is `00 11`
(17 bytes) because `a20-65.akam.net` is the **first** appearance of
`akam.net` in the message, so the suffix is written out in full:

```
06 "a20-65"  04 "akam"  03 "net"  00     = 17 bytes
```

Every later `.akam.net` record replaces that suffix with the two-byte
pointer `c0 32`, collapsing to 8 or 9 bytes:

```
06 "a24-66"  c0 32                        = 9 bytes
```

The same pattern repeats in the other family. Record 5 writes
`dnsmadeeasy.com` out in full at `00 15` (21 bytes); records 7 and 9 reuse
it via the pointer `c0 8a` and shrink to `00 06` (6 bytes).

So the first record of each domain family is long, and its siblings are
short because they point back into it.

Note that RDLENGTH depends on a record's **position** in the message, not
only on its name. 8.8.8.8 returns these nine nameservers in a rotating
order, so whichever `.akam.net` record happens to arrive first is the one
written out at `00 11`. In an earlier capture of this same query,
`a1-158.akam.net` came first and measured `00 11`; in the submitted
capture it arrives third and measures `00 09`. The values in the table
above are the ones in the submitted `project2_partB.pcap`.

## Q10. Why do the NS records appear in the Answer section rather than the Authority section?

Because we **asked for** them. The query carries QTYPE = `00 02` (NS) with
RD = 1, sent to a recursive resolver. The NS records are the direct answer
to the question that was asked, and answers belong in the Answer section.
This is confirmed by the counts: ANCOUNT = `00 09`, NSCOUNT = `00 00`.

The Authority section exists for a different situation: a server that
**cannot** answer the question and instead refers the client to servers
that can. In that case the NS records are not an answer, they are a
pointer onward, and they go in Authority along with glue addresses in
Additional.

Part C shows the contrast directly. There, the root server receives a
query for an A record it cannot answer, so it returns NS records in the
**Authority** section — the same record type, in a different section,
because it is delegating rather than answering. (Note the servers named
are different in the two cases: Part B returns Princeton's own nameservers
in `akam.net` and `dnsmadeeasy.com`, while Part C's root referral names the
`.edu` servers.)

---

# PART C — Iterative Resolver

Resolving `ilab1.cs.rutgers.edu` (A) with RD = 0, starting from the root.
Our traffic is **frames 1–6**; see open item 4 regarding frames 7–16.

## Wireshark Activity

**How many queries did the resolver send?** **Three.**

**Which servers did it contact?**

| # | Server IP | Who it is | Level |
|---|---|---|---|
| 1 | `198.41.0.4` | a.root-servers.net | Root |
| 2 | `192.31.80.30` | d.edu-servers.net | `.edu` TLD |
| 3 | `130.156.133.30` | dns2.rutgers.edu | `rutgers.edu` authoritative |

**At which level was the answer received?** At the **third** level — the
`rutgers.edu` authoritative server, which returned `128.6.13.2` with AA = 1
in frame 6. Each earlier server returned a referral rather than an answer.

The full walk:

```
frame 1  ->  198.41.0.4        query A ilab1.cs.rutgers.edu, RD=0
frame 2  <-  198.41.0.4        referral: 13 NS for .edu + 11 glue, TC=1, AA=0
frame 3  ->  192.31.80.30      same query
frame 4  <-  192.31.80.30      referral: 5 NS for rutgers.edu + 4 glue, AA=0
frame 5  ->  130.156.133.30    same query
frame 6  <-  130.156.133.30    ANSWER: A 128.6.13.2, AA=1
```

Note the question never changes. Only the destination changes, chosen each
time from the glue records in the previous response.

## Q11. Why is TC=1 in the first response (the response from the root server)?

Frame 2's flags are `0x8200`: QR=1, AA=0, **TC=1**, RD=0, RCODE=0.

DNS over UDP without EDNS0 is limited to **512 bytes** of DNS payload. The
root's referral for `.edu` needs to carry NSCOUNT = `00 0d` — thirteen
nameserver records — plus glue addresses for each. Complete glue would be
26 records (an A and an AAAA for all thirteen), but ARCOUNT is only
`00 0b`, **eleven**: six A records and five AAAA records. The resulting
payload is **497 bytes**, right against the limit.

So the server included as much as would fit, dropped the remaining fifteen
glue records, and set TC=1 to signal that the message is incomplete. A
client that needs the omitted data is expected to retry over TCP.

**A note on the project specification.** Page 2 states that for this
project the client must exit and return an error on a truncated response.
That general rule conflicts with this question, which presupposes that the
truncated root response is received and used — and in practice Part C
cannot work otherwise, since every root referral is truncated. Our Part C
resolver therefore continues after TC=1, because the glue it actually
needs survived the truncation. Parts A and B do enforce the exit-on-
truncation rule. (The separate RA rule on page 2 is explicitly scoped to
Parts A and B, and does not apply here because RD=0 in Part C.)

## Q12. Which of the three responses has AA=1? Why are AA=0 in the others?

| Frame | From | Flags | AA |
|---|---|---|---|
| 2 | 198.41.0.4 (root) | `0x8200` | **0** |
| 4 | 192.31.80.30 (.edu) | `0x8000` | **0** |
| 6 | 130.156.133.30 (rutgers.edu) | `0x8400` | **1** |

Only **frame 6** has AA=1.

The Authoritative Answer bit means the responding server is authoritative
for the name in the question section — that is, it actually holds the zone
containing that name and its answer is the definitive one.

The root server holds only the root zone; it knows which servers are
responsible for `.edu` and nothing more. The `.edu` server holds only the
`.edu` zone; it knows which servers are responsible for `rutgers.edu` and
nothing more. Neither one stores any record for `ilab1.cs.rutgers.edu`, so
neither can set AA. Each returns an empty Answer section with a referral in
Authority instead.

`dns2.rutgers.edu` does hold the zone, so it answers from its own
authoritative data and sets AA=1. This is also the resolver's stop
condition: an authoritative answer means the walk is finished.

## Q13. Type field in the first DNS query among the iterative messages (hex)

```
00 01
```

Frame 1's QTYPE field, requesting an A record (IPv4 address). QCLASS is
`00 01` (IN). The full flags word on this query is `0x0000`, confirming
RD=0 as Part C requires — Parts A and B send `0x0100`.

## Q14. Type field in the resource records of the first DNS response, by section

Frame 2, from the root server:

| Section | Count | Types present |
|---|---|---|
| **Answer** | 0 | *(empty — this is a referral, not an answer)* |
| **Authority** | 13 | All TYPE `00 02` (NS) |
| **Additional** | 11 | 6 × TYPE `00 01` (A), 5 × TYPE `00 1c` (AAAA) |

The thirteen Authority records are the `.edu` nameservers `a.edu-servers.net`
through `m.edu-servers.net`. The eleven Additional records are the glue
addresses for them — the IPv4 and IPv6 addresses that make the referral
usable. An empty Answer section with a populated Authority section is the
signature of a referral.

## Q15. Destination IP of the second DNS query (hex). Where is this IP found from?

Frame 3's destination IP is `192.31.80.30`:

```
c0 1f 50 1e
```

**It comes from the Additional (glue) section of the first response.**

The chain is visible directly in the capture:

```
frame 2, Authority  #1  ->  NS    edu = d.edu-servers.net     (first NS listed)
frame 2, Additional #1  ->  A     d.edu-servers.net = 192.31.80.30
frame 3, IP header      ->  Destination = 192.31.80.30
```

The resolver takes the first nameserver named in the Authority section,
looks up that hostname in the Additional section to find its address, and
sends the next query there.

This is the heart of iterative resolution, and it is why glue records
matter. The Authority section gives only *names* — `d.edu-servers.net` is
not something we can send a packet to. Without the matching A record in
Additional, resolving that hostname would itself require a full DNS
lookup, which is the chicken-and-egg problem glue exists to solve. The
project specification tells us to assume glue is always available and
return an error otherwise, which is what our implementation does.

The same mechanism produces the third hop: frame 4's Authority section
names `dns2.rutgers.edu` first, its Additional section gives
`dns2.rutgers.edu = 130.156.133.30`, and that is frame 5's destination.
