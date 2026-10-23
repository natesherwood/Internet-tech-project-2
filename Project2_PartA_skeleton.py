import socket
import struct
import random
import json
import os

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 1,      # recursion desired
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # Arecord
            "qclass": 1   # IN
        }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse answers
    answers = []
    for _ in range(ANCOUNT):
        # name (compression: first two bits 11)
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        if atype == 1 and rdlength == 4:        # A record -> IPv4 address
            ip = socket.inet_ntop(socket.AF_INET, rdata)
        elif atype == 28 and rdlength == 16:    # AAAA record -> IPv6 address
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            continue                            # not an address record (e.g. CNAME)

        answers.append({"type": atype, "ip": ip, "ttl": ttl})

    response["answers"] = answers
    return response


def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    # Check TC straight from the header: a genuinely truncated message can be
    # cut off mid-record, so parse_response may fail before we could check it.
    if (struct.unpack("!H", data[2:4])[0] >> 9) & 1:
        raise Exception("Response truncated (TC=1)")

    result=parse_response(data)

    if result["ra"] == 0:
        raise Exception("Server does not support recursion (RA=0)")

    return result


if __name__ == "__main__":
    # Read questions from file. Accept the PDF's input.txt or the provided
    # Input.json, and either a bare JSON list or {"questions": [...]}.
    path = "input.txt" if os.path.exists("input.txt") else "Input.json"
    with open(path, "r") as f:
        data = json.load(f)
    questions = data["questions"] if isinstance(data, dict) else data

    results = []
    for q in questions:
        spec = {"id": random.randint(0, 65535), "qr": 0, "opcode": 0, "rd": 1,
                "questions": [{"qname": q["qname"], "qtype": q["qtype"], "qclass": 1}]}
        response = dns_query(spec)
        print(json.dumps(response, indent=2))
        results.append(response)

    with open("output.txt", "w") as f:
        json.dump(results, f, indent=2)
