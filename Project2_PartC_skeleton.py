import socket
import struct
import random
import json

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 0,      # NO recursion - we iterate ourselves (Part C)
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # A record
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


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

def parse_rr(data, offset):
    """Parse a single resource record and return record + new offset."""
    name, offset = parse_name(data, offset)
    atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata_start = offset
    offset += rdlength                      # always advance by RDLENGTH

    record = {"hostname": name, "ttl": ttl, "atype": atype, "class": aclass,
              "rdlength": rdlength, "ip": None, "nsname": None}

    if atype == 1:                          # A
        record["rtype"] = "A"
        record["ip"] = socket.inet_ntop(socket.AF_INET, data[rdata_start:rdata_start+4])
    elif atype == 28:                       # AAAA
        record["rtype"] = "AAAA"
        record["ip"] = socket.inet_ntop(socket.AF_INET6, data[rdata_start:rdata_start+16])
    elif atype == 2:                        # NS
        record["rtype"] = "NS"
        record["nsname"], _ = parse_name(data, rdata_start)
    elif atype == 5:                        # CNAME
        record["rtype"] = "CNAME"
        record["nsname"], _ = parse_name(data, rdata_start)
    else:
        record["rtype"] = str(atype)
        record["rdata"] = data[rdata_start:rdata_start+rdlength].hex()

    return record, offset

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
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse Answer RRs
    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)
    # Parse Authority RRs (NS)
    authorities = []
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)

    # Parse Additional RRs (A, AAAA, etc.)
    additionals = []
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)
    
    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response



def dns_query(query_spec, server=("1.1.1.1", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(4096)
    sock.close()
    return parse_response(data)



def iterative_resolve(query_spec):
    servers = ["198.41.0.4"]#initialize with ip address of any root servers]
    print ("roort servers",servers)

    qname = query_spec["questions"][0]["qname"]
    qtype = query_spec["questions"][0]["qtype"]
    trace = []

    while servers:
        server_ip = servers.pop(0)
        response = dns_query(query_spec, server=(server_ip, 53))
        trace.append(server_ip)
        print("  queried %s  aa=%s tc=%s an=%s ns=%s ar=%s" % (
            server_ip, response["aa"], response["tc"],
            response["ancount"], response["nscount"], response["arcount"]))

        if response["rcode"] == 3:
            return {"error": "NXDOMAIN: %s does not exist" % qname,
                    "servers_contacted": trace}
        if response["rcode"] != 0:
            return {"error": "RCODE %s from %s" % (response["rcode"], server_ip),
                    "servers_contacted": trace}

        # 1. do we have the answer?
        ips = [rr["ip"] for rr in response["answers"]
               if rr["atype"] == qtype and rr["ip"]]
        if ips:
            return {"qname": qname, "qtype": qtype, "aa": response["aa"],
                    "addresses": ips, "servers_contacted": trace}

        # 2. referral: match NS names in authority against glue in additional
        ns_names = [rr["nsname"] for rr in response["authorities"]
                    if rr["atype"] == 2]
        glue = {rr["hostname"].lower(): rr["ip"] for rr in response["additionals"]
                if rr["atype"] == 1 and rr["ip"]}

        new_server = None
        for n in ns_names:
            if n and n.lower() in glue:
                new_server = glue[n.lower()]
                break

        # 3. no glue -> exit
        if not new_server:
            return {"error": "No glue found", "ns_names": ns_names,
                    "servers_contacted": trace}

        servers = [new_server]

    return {"error": "ran out of servers", "servers_contacted": trace}




if __name__ == "__main__":
    response = iterative_resolve(dns_query_spec)
    
    print(json.dumps(response,indent=2))
    