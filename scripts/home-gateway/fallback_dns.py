#!/usr/bin/env python3
"""Small standby UDP/TCP DNS forwarder, used only if the main gateway stops."""
import argparse
import ipaddress
import json
import socket
import socketserver
import struct
import threading

SLOTS = threading.BoundedSemaphore(64)


def receive(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise OSError('Incomplete DNS frame')
        result += part
    return result


def serve(config):
    allowed = ipaddress.IPv4Network(config['lan_cidr'])

    class Threads(socketserver.ThreadingMixIn):
        daemon_threads = True

        def process_request(self, request, address):
            if not SLOTS.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except Exception:
                SLOTS.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                SLOTS.release()

        def verify_request(self, request, address):
            ip = ipaddress.IPv4Address(address[0])
            return ip in allowed or ip.is_loopback

        def handle_error(self, request, address):
            pass

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, downstream = self.request
            if not 12 <= len(query) <= 65535:
                return
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(3)
                upstream.connect((config['upstream'], config.get('upstream_port', 53)))
                upstream.send(query)
                answer = upstream.recv(65535)
            if answer[:2] == query[:2]:
                downstream.sendto(answer, self.client_address)

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(4)
            length = struct.unpack('!H', receive(self.request, 2))[0]
            query = receive(self.request, length)
            if length < 12:
                return
            with socket.create_connection((config['upstream'], config.get('upstream_port', 53)), timeout=3) as upstream:
                upstream.sendall(struct.pack('!H', length) + query)
                size = struct.unpack('!H', receive(upstream, 2))[0]
                answer = receive(upstream, size)
            if answer[:2] == query[:2]:
                self.request.sendall(struct.pack('!H', len(answer)) + answer)

    class UDPServer(Threads, socketserver.UDPServer):
        max_packet_size = 65535

    class TCPServer(Threads, socketserver.TCPServer):
        allow_reuse_address = True

    address = (config['listen'], config.get('port', 53))
    with UDPServer(address, UDP) as udp, TCPServer(address, TCP) as tcp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        udp.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    serve(json.load(open(parser.parse_args().config)))
