#!/usr/bin/env python3
import logging
import random
import socket
import sys

logging.basicConfig(level=logging.INFO)

SWITCH_MSB = False
ZERO_LENGTH_OCTET = "00000000"
OCTET_SIZE = 8
HOST, PORT = "198.41.0.4", 53

RANDOM_ID = None


def build_header(ID):
    """header: id, flags, counts"""
    ID = f"{ID:016b}"
    qr = "0"
    opcode = "0000"
    aa = "0"
    tc = "0"
    rd = "0"
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


def build_request(domain, random_id):
    global SWITCH_MSB
    header = build_header(random_id)
    question = build_question(domain)
    request = header + question
    if request.startswith("0"):
        request = "1" + request[1:]
        SWITCH_MSB = True
    request = f"{int(request, 2):x}"
    return request


def send_request_and_receive_response(request):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect_ex((HOST, PORT))
    s.sendall(bytes.fromhex(request))
    response = s.recv(1024)
    s.close()
    response = response.hex()
    response = f"{int(response, 16):b}"
    if SWITCH_MSB:
        response = "0" + response[1:]
    # logging.debug(f"{response=}")
    return response


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


def handle_pointer(response, start):
    prefix, start = read_bits(response, start, 2)
    offset, start = read_bits(response, start, 14, as_int=True)
    return parse_name(response, offset * OCTET_SIZE)[0], start


def parse_name(response, start):
    if response[start : start + 2] == "11":
        # logging.debug("parse_name | pointer at start")
        return handle_pointer(response, start)
    parts = []
    name_from_pointer = ""
    while True:
        # check pointer
        if response[start : start + 2] == "11":
            # logging.debug("parse_name | pointer at end")
            name_from_pointer, start = handle_pointer(response, start)
            break
        else:
            length, start = read_bits(response, start, OCTET_SIZE)

        length = int(length, 2)
        if length == 0:
            break
        part = []
        for _ in range(length):
            char_octet, start = read_bits(response, start, OCTET_SIZE)
            char = chr(int(char_octet, 2))
            part.append(char)
        parts.append(part)
    name = (".".join("".join(part) for part in parts + [name_from_pointer])).rstrip(".")
    return name, start


def parse_question(response, start):
    """question: name, type, class"""
    qname, start = parse_name(response, start)
    qtype, start = read_bits(response, start, 16, as_int=True)
    qclass, start = read_bits(response, start, 16, as_int=True)
    question = {k: v for k, v in locals().items() if k not in ("response", "start")}
    return question, start


def parse_rdata(response, start, rdlength, rtype, rclass):
    if rtype == 1 and rclass == 1:
        # logging.debug("ARPA Internet address")
        parts = []
        for _ in range(rdlength):
            part, start = read_bits(response, start, OCTET_SIZE, as_int=True)
            parts.append(part)
        return ".".join(map(str, parts)), start
    elif rtype == 2 and rclass == 1:
        # logging.debug("authoritative name server")
        name, start = parse_name(response, start)
        return name, start
    elif rtype == 28 and rclass == 1:
        # TODO: handle this later
        # logging.debug("ipv6")
        _, start = read_bits(response, start, 128)
        return "ipv6", start
    else:
        raise Exception(f"Unspported rtype/rclass | {rtype=} | {rclass=}")


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


def parse_response(response):
    start = 0
    header, start = parse_header(response, start)
    logging.debug(f"{header=}")

    question, start = parse_question(response, start)
    logging.debug(f"{question=}")

    answer_list = []
    for _ in range(header["ancount"]):
        answer, start = parse_resource_record(response, start)
        logging.debug(f"{answer=}")
        answer_list.append(answer)

    authority_list = []
    for _ in range(header["nscount"]):
        authority, start = parse_resource_record(response, start)
        logging.debug(f"{authority=}")
        authority_list.append(authority)

    additional_list = []
    for _ in range(header["arcount"]):
        additional, start = parse_resource_record(response, start)
        logging.debug(f"{additional=}")
        additional_list.append(additional)

    return {
        "header": header,
        "question": question,
        "answer": answer_list,
        "authority": authority_list,
        "additional": additional_list,
    }


def main(domain):
    global RANDOM_ID, HOST
    random_id = RANDOM_ID = random.randint(1, 100)
    print(f"querying {HOST} for {domain}")
    request = build_request(domain + ".", random_id)
    response = send_request_and_receive_response(request)
    parsed_response = parse_response(response)
    if parsed_response["answer"]:
        return parsed_response["answer"]
    else:
        if parsed_response["additional"]:
            additional_ips = [
                r["rdata"] for r in parsed_response["additional"] if r["rtype"] == 1
            ]
            HOST = additional_ips[0]
            return main(domain)
        else:
            authority_names = [r["rdata"] for r in parsed_response["authority"]]
            answers = main(authority_names[0])
            if answers:
                HOST = answers[0]["rdata"]
                return main(domain)


if __name__ == "__main__":
    try:
        domain = sys.argv[1]
    except IndexError:
        raise Exception("No domain provided")
    answers = main(domain)
    for answer in answers:
        print(answer)
