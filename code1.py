import socket 
import sqlite3
import cowsay

from datetime import datetime

HOST =  "0.0.0.0"
PORT = 22

connection = sqlite3.connect("honeyport.db")
cursor = connection.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, ip VARCHAR(45) NOT NULL, ip_time TEXT)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(10),
    scan_type TEXT,
    event_time TEXT
)
""")
cursor.execute("""CREATE TABLE IF NOT EXISTS raw_packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    packet_time TEXT,
    payload BLOB,
    FOREIGN KEY(event_id) REFERENCES events(id)
)
""")


def detect_scan_type(data):
    text = data.lower()
    if 'nmap' in text:
        return 'nmap'
    if 'masscan' in text:
        return 'masscan'
    if 'zgrab' in text:
        return 'zgrab'
    if 'ssh-' in text or 'ssh' in text:
        return 'ssh'
    if 'scan' in text:
        return 'scan'
    if len(text.strip()) == 0:
        return 'empty'
    return 'unknown'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print(f"Listening on {PORT}")

while True:
    client,addr = server.accept()
    try:
        print(f"[{datetime.now()}] Connection from {addr}")

        ip = addr[0]
        src_port = addr[1]
        dest_port = PORT
        proto = "TCP"
        ip_time = datetime.now().isoformat()

        scan_type = 'unknown'
        payload_chunks = []
        try:
            client.send(cowsay.get_output_string("turkey", "what did you see, welcome to the Big Boss 2.0 ").encode())
            client.settimeout(0.8)
            while True:
                packet = client.recv(4096)
                if not packet:
                    break
                payload_chunks.append(packet)
        except socket.timeout:
            pass
        except Exception:
            pass

        if payload_chunks:
            all_payload = b''.join(payload_chunks)
            try:
                decoded = all_payload.decode(errors='ignore')
                scan_type = detect_scan_type(decoded)
                print(decoded)
            except Exception:
                scan_type = 'unknown'

        # keep the old users table for compatibility
        query = "INSERT INTO users (ip, ip_time) VALUES (?, ?)"
        cursor.execute(query, (ip, ip_time))

        # log richer event data for statistics
        evt_q = "INSERT INTO events (src_ip, src_port, dest_port, protocol, scan_type, event_time) VALUES (?, ?, ?, ?, ?, ?)"
        cursor.execute(evt_q, (ip, src_port, dest_port, proto, scan_type, ip_time))
        event_id = cursor.lastrowid

        for packet in payload_chunks:
            packet_time = datetime.now().isoformat()
            packet_q = "INSERT INTO raw_packets (event_id, packet_time, payload) VALUES (?, ?, ?)"
            cursor.execute(packet_q, (event_id, packet_time, sqlite3.Binary(packet)))

        connection.commit()
    finally:
        client.close()

    
