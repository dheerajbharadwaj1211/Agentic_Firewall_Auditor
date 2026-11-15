"""Unprivileged TCP test endpoint: fixed response only; never serves files."""
import socket


def main():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind(('192.168.56.30',3306))
        server.listen(16)
        server.settimeout(1)
        print('LAB TCP service listening on 192.168.56.30:3306. This is not MySQL. Ctrl+C stops it.',flush=True)
        try:
            while True:
                try:connection,address=server.accept()
                except socket.timeout:continue
                with connection:
                    connection.settimeout(1)
                    try:connection.sendall(b'Firewall Auditor lab endpoint\n')
                    except OSError:pass
        except KeyboardInterrupt:
            print('Lab endpoint stopped.')


if __name__=='__main__':main()
