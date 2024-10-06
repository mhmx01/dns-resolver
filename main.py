#!/usr/bin/env python3
import logging
import random
import socket
import sys

logging.basicConfig(level=logging.INFO)

SWITCH_MSB = False
ZERO_LENGTH_OCTET = "00000000"
OCTET_SIZE = 8
HOST, PORT = "8.8.8.8", 53

RANDOM_ID = random.randint(1, 100)
try:
    domain = sys.argv[1] + "."
except IndexError:
    raise Exception("No domain provided")


def build_header(ID):
    """header: id, flags, counts"""
    ID = f"{ID:016b}"
    qr = "0"
    opcode = "0000"
    aa = "0"
    tc = "0"
    rd = "1"
    ra = "0"
    z = "000"
    rcode = "0000"
    qdcount = f"{1:016b}"
    ancount = "0" * 16
    nscount = "0" * 16
    arcount = "0" * 16
    return "".join(locals().values())


def build_question(domain):
    """question: name, type, class"""
    qname = "".join(
        f"{len(part):08b}" + "".join(f"{ord(c):08b}" for c in part)
        for part in domain.split(".")
    )
    qtype = f"{1:016b}"
    qclass = f"{1:016b}"
    return "".join(v for k, v in locals().items() if k != "domain")


def read_bits(bit_string, start, size, as_int=False):
    bits = bit_string[start : start + size]
    start += size
    if as_int:
        return int(bits, 2), start
    return bits, start


def parse_header(response, start):
    """header: id, flags, counts"""
    ID, start = read_bits(response, start, 16, as_int=True)
    assert ID == RANDOM_ID
    qr, start = read_bits(response, start, 1)
    assert qr == "1"  # response
    opcode, start = read_bits(response, start, 4)
    aa, start = read_bits(response, start, 1)
    tc, start = read_bits(response, start, 1)
    rd, start = read_bits(response, start, 1)
    ra, start = read_bits(response, start, 1)
    z, start = read_bits(response, start, 3)
    rcode, start = read_bits(response, start, 4)
    qdcount, start = read_bits(response, start, 16, as_int=True)
    ancount, start = read_bits(response, start, 16, as_int=True)
    nscount, start = read_bits(response, start, 16, as_int=True)
    arcount, start = read_bits(response, start, 16, as_int=True)
    header = {k: v for k, v in locals().items() if k not in ("response", "start")}
    return header, start


def parse_name(response, start):
    if response[start : start + 2] == "11":
        logging.debug("pointer")
        prefix, start = read_bits(response, start, 2)
        offset, start = read_bits(response, start, 14, as_int=True)
        return parse_name(response, offset * OCTET_SIZE)[0], start
    parts = []
    while (
        t := read_bits(response, start, OCTET_SIZE, as_int=True)
    ) != ZERO_LENGTH_OCTET:
        length, start = t
        if length == 0:
            break
        part = []
        for _ in range(length):
            char_octet, start = read_bits(response, start, OCTET_SIZE)
            char = chr(int(char_octet, 2))
            part.append(char)
        parts.append(part)
    return ".".join("".join(part) for part in parts), start


def parse_question(response, start):
    """question: name, type, class"""
    qname, start = parse_name(response, start)
    qtype, start = read_bits(response, start, 16, as_int=True)
    qclass, start = read_bits(response, start, 16, as_int=True)
    question = {k: v for k, v in locals().items() if k not in ("response", "start")}
    return question, start


def parse_rdata(response, start, rdlength, rtype, rclass):
    if rtype == 1 and rclass == 1:
        logging.debug("ARPA Internet address")
        parts = []
        for _ in range(rdlength):
            part, start = read_bits(response, start, OCTET_SIZE, as_int=True)
            parts.append(part)
    else:
        raise Exception("Unspported rtype/rclass")
    return ".".join(map(str, parts)), start


def parse_resource_record(response, start):
    """resource records (answer/authority/additional): name, type, class, ttl, rdlength, rdata"""
    rname, start = parse_name(response, start)
    rtype, start = read_bits(response, start, 16, as_int=True)
    rclass, start = read_bits(response, start, 16, as_int=True)
    ttl, start = read_bits(response, start, 32, as_int=True)
    rdlength, start = read_bits(response, start, 16, as_int=True)
    rdata, start = parse_rdata(response, start, rdlength, rtype, rclass)
    rrecord = {k: v for k, v in locals().items() if k not in ("response", "start")}
    return rrecord, start


# build request
header = build_header(RANDOM_ID)
question = build_question(domain)
request = header + question
if request.startswith("0"):
    request = "1" + request[1:]
    SWITCH_MSB = True
request = f"{int(request, 2):x}"

# send request, receive response
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect_ex((HOST, PORT))
s.sendall(bytes.fromhex(request))
response = s.recv(1024)

# parse response
response = response.hex()
response = f"{int(response, 16):b}"
if SWITCH_MSB:
    response = "0" + response[1:]
logging.debug(f"{response=}")

start = 0
header, start = parse_header(response, start)
logging.debug(f"{header=}")

question, start = parse_question(response, start)
logging.debug(f"{question=}")

for _ in range(header["ancount"]):
    answer, start = parse_resource_record(response, start)
    logging.info(f"{answer=}")

for _ in range(header["nscount"]):
    authority, start = parse_resource_record(response, start)
    logging.info(f"{authority=}")

for _ in range(header["arcount"]):
    additional, start = parse_resource_record(response, start)
    logging.info(f"{additional=}")
