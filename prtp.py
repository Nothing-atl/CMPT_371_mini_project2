
import socket
import struct
import threading
import time
import random

HEADER_FMT = "!IIBHHH"  # seq, ack, flags, rwnd, length, checksum...
HEADER_SIZE = struct.calcsize(HEADER_FMT)

FLAG_SYN = 0x1
FLAG_ACK = 0x2
FLAG_FIN = 0x4
FLAG_DATA = 0x8

MSS = 1000          # bytes of app data per segment...
DEFAULT_TIMEOUT = 0.5  # seconds...


def compute_checksum(data: bytes) -> int:
    # very simple 16-bit checksum: sum of bytes
    # keep only the lower 16 bits...
    s = sum(data) & 0xFFFF
    return s


def make_packet(seq: int, ack: int, flags: int, rwnd: int, payload: bytes) -> bytes:
    """
    Steps:
      1. Pack the header with a temporary checksum of 0...
      2. Compute checksum over header+payload.
      3. Pack the header again, this time with the real checksum.
      4. Return header + payload as the wire format....
      
      """
    length = len(payload)
    # First pass header: checksum field is 0 so we can compute it
    header_wo_checksum = struct.pack(HEADER_FMT, seq, ack, flags, rwnd, length, 0)
    # checksum over header+payload.
    checksum = compute_checksum(header_wo_checksum + payload)
    #  Pack the header again, this time with the real checksum...
    header = struct.pack(HEADER_FMT, seq, ack, flags, rwnd, length, checksum)
    
    return header + payload


def parse_packet(raw: bytes):
    
    # not even enough bytes for a header – just drop it...
    if len(raw) < HEADER_SIZE:
        return None
    
    # peel off the header fields...
    seq, ack, flags, rwnd, length, checksum = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    # extract the payload based on the advertised length...
    payload = raw[HEADER_SIZE:HEADER_SIZE + length]
    # reconstruct the header with checksum=0 to recompute it...
    
    header = struct.pack(HEADER_FMT, seq, ack, flags, rwnd, length, 0)
    # if checksums don’t match, we treat it as corruption and drop the packet....
    
    if compute_checksum(header + payload) != checksum:
        return None
    
    # all good: hand the fields back to the protocol logic
    return seq, ack, flags, rwnd, payload


class ReliableSocket:
    """
    Very small connection-oriented, reliable, pipelined protocol over UDP.
    
    Features:
      * 3-way handshake (SYN, SYN-ACK, ACK)
      * Sliding window with Go-Back-N semantics
      * Flow control (rwnd)
      * Congestion control (slow start + AIMD like TCP Reno)
      * Loss and corruption simulation via _udt_send()
    """
    def __init__(self, loss_prob=0.0, corrupt_prob=0.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.1)
        self.peer = None

        # loss/error simulation
        self.loss_prob = loss_prob
        self.corrupt_prob = corrupt_prob

        # sending side state
        self.send_lock = threading.Lock()
        self.send_base = 0
        self.next_seq = 0
        self.send_buffer = {}   # seq -> (packet_bytes, last_sent_time)
        self.running = False

        # congestion control
        self.cwnd = 1          # in segments
        self.ssthresh = 16
        self.ack_count = 0

        # flow control
        self.remote_rwnd = 32  # in segments

        # receiving side
        self.recv_lock = threading.Lock()
        self.expected_seq = 0
        self.recv_buffer = bytearray()
        self.app_closed = False

        self.ack_thread = None

    # ---------- Underlying send/recv with random loss/corruption ----------

    def _udt_send(self, data: bytes):
        if random.random() < self.loss_prob:
            # drop packet
            return
        # maybe corrupt one byte
        if data and random.random() < self.corrupt_prob:
            idx = random.randrange(len(data))
            flipped = bytes([data[idx] ^ 0xFF])
            data = data[:idx] + flipped + data[idx + 1:]
        self.sock.sendto(data, self.peer)

    def _udt_recv(self, bufsize=2048):
        try:
            raw, addr = self.sock.recvfrom(bufsize)
            return raw, addr
        except socket.timeout:
            return None, None

    # ---------- Connection management ----------

    def bind(self, addr):
        self.sock.bind(addr)

    def listen(self):
        # just to mimic TCP API
        pass
        
    def accept(self):
        """
        Block waiting for a SYN, then perform handshake and
        return a new ReliableSocket for the connection.
        server does NOT start an ACK thread; it will
        handle packets in conn.recv().
        """
        print("[SERVER] Waiting for SYN...")
        while True:
            raw, addr = self._udt_recv()
            if not raw:
                continue
            print(f"[SERVER] Got raw packet of length {len(raw)} from {addr}")
            parsed = parse_packet(raw)
            print(f"[SERVER] Parsed packet: {parsed}")
            if not parsed:
                continue
            seq, ack, flags, rwnd, payload = parsed
            if flags & FLAG_SYN:
                print("[SERVER] Received SYN, sending SYN-ACK")
                # create child socket object for this connection
                conn = ReliableSocket(self.loss_prob, self.corrupt_prob)
                conn.sock = self.sock      # share underlying socket
                conn.peer = addr
                conn.running = True
                conn.expected_seq = seq + 1

                # send SYN-ACK
                synack = make_packet(
                    seq=0,
                    ack=conn.expected_seq,
                    flags=FLAG_SYN | FLAG_ACK,
                    rwnd=conn._available_rwnd(),
                    payload=b"",
                )
                conn._udt_send(synack)

                # wait for final ACK
                start = time.time()
                print("[SERVER] Waiting for final ACK...")
                while time.time() - start < 2.0:
                    raw2, addr2 = conn._udt_recv()
                    if not raw2:
                        continue
                    print(f"[SERVER] Got raw2 len={len(raw2)} from {addr2}")
                    parsed2 = parse_packet(raw2)
                    print(f"[SERVER] Parsed2: {parsed2}")
                    if not parsed2:
                        continue
                    seq2, ack2, flags2, rwnd2, payload2 = parsed2
                    if flags2 & FLAG_ACK and ack2 == conn.expected_seq:
                        print("[SERVER] Handshake complete.")
                        
                        return conn, addr


    def connect(self, addr):
        """
        Client side 3-way handshake.
        """
        self.peer = addr
        self.running = True
        self.send_base = 0
        self.next_seq = 1  # ISN = 0, first data = 1

        print(f"[CLIENT] Sending SYN to {addr}")
        # send SYN
        syn = make_packet(
            seq=0,
            ack=0,
            flags=FLAG_SYN,
            rwnd=self._available_rwnd(),
            payload=b"",
        )
        self._udt_send(syn)

        print("[CLIENT] Waiting for SYN-ACK...")
        # wait for SYN-ACK
        while True:
            raw, _ = self._udt_recv()
            if not raw:
                continue
            print(f"[CLIENT] Got raw packet len={len(raw)}")
            parsed = parse_packet(raw)
            print(f"[CLIENT] Parsed: {parsed}")
            if not parsed:
                continue
            seq, ack, flags, rwnd, payload = parsed
            if (flags & FLAG_SYN) and (flags & FLAG_ACK):
                print("[CLIENT] Received SYN-ACK, sending final ACK")
                self.remote_rwnd = max(1, rwnd)
                # send final ACK
                ackpkt = make_packet(
                    seq=self.next_seq,
                    ack=seq + 1,
                    flags=FLAG_ACK,
                    rwnd=self._available_rwnd(),
                    payload=b"",
                )
                self._udt_send(ackpkt)
                self._start_ack_thread()
                return

    def close(self):
        # send FIN and wait a bit
        fin = make_packet(
            seq=self.next_seq,
            ack=0,
            flags=FLAG_FIN,
            rwnd=self._available_rwnd(),
            payload=b"",
        )
        self._udt_send(fin)
        self.running = False
        time.sleep(0.5)
        self.sock.close()

    # ---------- Sending / receiving data ----------

    def send(self, data: bytes):
        """
        Blocking send. Splits data into segments and uses sliding window.
        """
        offset = 0
        while offset < len(data):
            with self.send_lock:
                window_size = min(self.cwnd, self.remote_rwnd)
                in_flight = len(self.send_buffer)   
                if in_flight >= window_size:
                    # window full; wait outside the lock
                    pass
                else:
                    # send next segment
                    chunk = data[offset:offset + MSS]
                    seg_seq = self.next_seq
                    pkt = make_packet(
                        seq=seg_seq,
                        ack=0,
                        flags=FLAG_DATA,
                        rwnd=self._available_rwnd(),
                        payload=chunk,
                    )
                    self.send_buffer[seg_seq] = (pkt, time.time())
                    self._udt_send(pkt)
                    self.next_seq += 1
                    offset += len(chunk)
                    continue  # try to send more immediately

            # outside lock: either window is full or nothing to send
            self._handle_timeouts()
            time.sleep(0.01)

        # wait until all data is acknowledged
        while True:
            with self.send_lock:
                if self.send_base == self.next_seq:
                    break
            self._handle_timeouts()
            time.sleep(0.01)


    def recv(self, bufsize: int = 4096) -> bytes:
        """
        Blocking receive for up to bufsize bytes from app buffer.
        """
        while True:
            with self.recv_lock:
                if len(self.recv_buffer) > 0:
                    n = min(bufsize, len(self.recv_buffer))
                    data = self.recv_buffer[:n]
                    del self.recv_buffer[:n]
                    return bytes(data)
                if self.app_closed:
                    return b""
            # no app data yet, check network
            raw, addr = self._udt_recv()
            if raw:
                self._handle_incoming(raw, addr)
            else:
                time.sleep(0.01)

    # ---------- Internal helpers ----------

    def _available_rwnd(self) -> int:
        # simple fixed receive window: how many more segments we can buffer
        max_buf_segments = 64
        # safe even if called while holding recv_lock
        used = (len(self.recv_buffer) + MSS - 1) // MSS
        return max(1, max_buf_segments - used)


    def _start_ack_thread(self):
        self.ack_thread = threading.Thread(target=self._ack_listener, daemon=True)
        self.ack_thread.start()

    def _ack_listener(self):
        while self.running:
            raw, addr = self._udt_recv()
            if not raw:
                self._handle_timeouts()
                continue
            self._handle_incoming(raw, addr)

    def _handle_incoming(self, raw: bytes, addr):
        parsed = parse_packet(raw)
        if not parsed:
            # checksum failed; drop
            return
        seq, ack, flags, rwnd, payload = parsed

        # update peer address in case of first packet
        if self.peer is None:
            self.peer = addr

        # update flow control
        if rwnd > 0:
            self.remote_rwnd = rwnd

        if flags & FLAG_ACK:
            self._handle_ack(ack)

        if flags & FLAG_DATA:
            self._handle_data(seq, payload)

        if flags & FLAG_FIN:
            with self.recv_lock:
                self.app_closed = True

    def _handle_ack(self, ack_num: int):
        with self.send_lock:
            if ack_num <= self.send_base:
                # duplicate ACK – you could extend with fast retransmit
                return
            # new ACK; remove all segments < ack_num
            keys_to_delete = [k for k in self.send_buffer.keys() if k < ack_num]
            for k in keys_to_delete:
                del self.send_buffer[k]
            self.send_base = ack_num

            # congestion control
            self.ack_count += 1
            if self.cwnd < self.ssthresh:
                # slow start: exponential
                self.cwnd += 1
            else:
                # congestion avoidance: cwnd += 1 per cwnd ACKs
                if self.ack_count >= self.cwnd:
                    self.cwnd += 1
                    self.ack_count = 0

    def _handle_data(self, seq: int, payload: bytes):
        with self.recv_lock:
            if seq == self.expected_seq:
                self.recv_buffer.extend(payload)
                self.expected_seq += 1
            print(f"[SERVER] DATA received seq={seq}, payload_len={len(payload)}")
            ackpkt = make_packet(
                seq=0,
                ack=self.expected_seq,
                flags=FLAG_ACK,
                rwnd=self._available_rwnd(),
                payload=b"",
            )
        self._udt_send(ackpkt)


    def _handle_timeouts(self):
        """
        Check for timeout of oldest unacked segment.
        """
        with self.send_lock:
            if not self.send_buffer:
                return
            oldest_seq = min(self.send_buffer.keys())
            pkt, ts = self.send_buffer[oldest_seq]
            if time.time() - ts > DEFAULT_TIMEOUT:
                # timeout: congestion event
                self.ssthresh = max(2, self.cwnd // 2)
                self.cwnd = 1
                # retransmit all unacked packets
                for seq, (pkt_bytes, _) in list(self.send_buffer.items()):
                    self.send_buffer[seq] = (pkt_bytes, time.time())
                    self._udt_send(pkt_bytes)



def run_server(listen_host="0.0.0.0", listen_port=9000, outfile="received.bin"):
    # TURN OFF LOSS FOR DEBUGGING, so here i put 0.0 for loss...
    # put 0.1 and 0.01 later in wireshark
    rsock = ReliableSocket(loss_prob=0.0, corrupt_prob=0.0)
    rsock.bind((listen_host, listen_port))
    rsock.listen()
    print(f"[SERVER] Listening on {listen_host}:{listen_port}")
    conn, addr = rsock.accept()
    print(f"[SERVER] Accepted connection from {addr}")
    with open(outfile, "wb") as f:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            f.write(data)
    print("[SERVER] File received, closing.")
    conn.close()


def run_client(server_host="127.0.0.1", server_port=9000, infile="to_send.bin"):
    # TURN OFF LOSS FOR DEBUGGING, same here put 0.0 for now...
    # put 0.1 and 0.01 later in wireshark
    rsock = ReliableSocket(loss_prob=0.0, corrupt_prob=0.0)
    print(f"[CLIENT] Connecting to {(server_host, server_port)}")
    rsock.connect((server_host, server_port))
    print(f"[CLIENT] Connected to {server_host}:{server_port}")
    with open(infile, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            rsock.send(chunk)
    print("[CLIENT] File sent, closing.")
    rsock.close()



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--infile", default="to_send.bin")
    parser.add_argument("--outfile", default="received.bin")
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.host, args.port, args.outfile)
    else:
        run_client(args.host, args.port, args.infile)
