import socket
import threading
import string
import random
import sys
import signal
import time
import os
from urllib import parse

OK = 200
NOT_FOUND = 404
BAD_REQUEST = 400
NOT_ALLOWED = 405
INTERNAL_SERVER_ERROR = 500
HTTP_VERSION_NOT_SUPPORTED = 505
HTML_ERROR = """<html>
<head>
<title>{status} - {text}</title>
</head>
<body>
<h1>{status}</h1>
<p>{text}</p>
</body>
</html>
"""


class HelloServer:
    """
    Simply TCP Server:
    request: "My name is Alex"
    response: "Hello, Alex"
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.read_size = 1024

    def start(self):
        """ Attempts to aquire the socket and launch the server """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            print("Launching HTTP server on ", self.host, ":", self.port)
            self.sock.bind((self.host, self.port))

        except Exception as e:
            print("ERROR: Failed to acquire sockets for port", self.port)
            print("Try running the Server in a privileged user mode.")
            self.shutdown()
            import sys
            sys.exit(1)

        print("Server successfully acquired the socket with port:", self.port)
        print("Press Ctrl+C to shut down the server and exit.")
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as executor:
            print('STARTING LISTEN')
            future = executor.submit(self._listen, ('LISTEN ' + self._get_th_key(),))
            future = executor.submit(self._listen, ('LISTEN ' + self._get_th_key(),))
            future = executor.submit(self._listen, ('LISTEN ' + self._get_th_key(),))
            print('LISTEN STARTED')
        print("BEHIND WITH")
        # self._listen()

    def _get_th_key(self):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

    def _listen(self, lkey):
        self.sock.listen(5)
        while True:
            print(f'{lkey}: ACCEPTING')
            client, address = self.sock.accept()
            print(f'{lkey}: ADDRESS: ', address)
            print(f'{lkey}: SET TIMEOUT')
            client.settimeout(10)
            key = self._get_th_key()
            print(f"{lkey}: START NEW THREAD WITH KEY", key)
            threading.Thread(target = self.listen_to_client, args = (client, address, key)).start()
            print(f'{lkey}: ALL TASKS COMPLETE')

    def listen_to_client(self, client, address, key):
        print(f'{key} : STARTED NEW THREAD FOR {address}')
        while True:
            try:
                print(f'{key} : GETTING DATA')
                data = self._read(client)
                print(f'{key} : DATA IS: {data}')
                if data:
                    response = self.get_response(data)
                    print(f'{key} : RESPONSE IS: {response}')
                    client.send(response)
                else:
                    raise socket.error('Client disconnected')
            except OSError as e:
                print(f'{key} : CLIENT DISCONNECTED, EXITING')
                client.close()
                return False

    def _read(self, client):
        data = client.recv(self.read_size)
        return data

    def get_response(self, data: bytes) -> bytes:
        data = data.decode()
        if ' is ' in data:
            name = data.split('is ')[-1]
            response = f'Hello, {name}!'
            return response.encode()
        else:
            return b'Unknown hello string'

    def shutdown(self, sig=None, dummy=None):
        """ Shut down the server """
        exit_code = 0
        try:
            print("Shutting down the server")
            self.sock.shutdown(socket.SHUT_RDWR)

        except Exception as e:
            print("Warning: could not shut down the socket. Maybe it was already closed?", e)
            exit_code = 1

        finally:
            sys.exit(exit_code)


class HTTPServer(HelloServer):
    def __init__(self, host, port):
        self.document_root = 'www'
        self.delimiter = b'\r\n'
        self.ender = b'\r\n\r\n'
        super().__init__(host, port)

    def _read(self, client):
        maxsize = 65536
        data = bytearray()
        while self.ender not in data:
            data += client.recv(self.read_size)
            if len(data) > maxsize:
                raise TypeError('HTTP request is too big')  # TODO: ERROR 400
        return data

    def _get_headers(self, data):
        """Only \r\n delimiter syntax is supported"""
        command, path, version = '', '', ''
        requestline = str(data, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        requestline = requestline.split('\r\n')[0]
        words = requestline.split()
        print('WORDS: ', words)
        if len(words) == 3:
            command, path, version = words
            try:
                if version[:5] != 'HTTP/':
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                return dict(), (BAD_REQUEST, "Bad request version (%r)" % version)
            if version_number >= (2, 0):
                return dict(), (HTTP_VERSION_NOT_SUPPORTED, "Invalid HTTP version (%s)" % base_version_number)
        elif len(words) == 2:
            command, path = words
        elif not words:
            return dict(), (BAD_REQUEST,  "Bad request syntax (%r)" % requestline)
        else:
            return dict(), (BAD_REQUEST,  "Bad request syntax (%r)" % requestline)
        if command not in ['GET', 'HEAD']:
            return dict(), (NOT_ALLOWED, "Method not allowed: (%r)" % command)
        headers = {
            'command': command,
            'path': path,
            'request_version': version
        }
        return headers, tuple()

    def get_html_from_path(self, path):
        html = b''
        try:
            print('TRY OPEN FILE', path)
            with open(path, 'rb') as f:
                html = f.read()
        except Exception as e:
            print("EXCEPTION")
            print(e.args)  # TODO: DEBUG MODE

        return html

    def resolve_path(self, path: str) -> str:
        print('PATH GETTED', path)
        if '%' in path:
            path = parse.unquote(path)
        if path == '/':
            path = os.path.join(self.document_root, 'index.html')
        else:
            path = self.document_root + path
        print('PATH IS', path)
        if os.path.isdir(path):
            path = os.path.join(path, 'index.html')  # 'htm' extension is not supported
        print('END PATH', path)
        return path

    def _gen_headers(self, code, content_length, content_type):
        """ Generates HTTP response Headers."""

        # determine response code
        h = ''
        if code == 200:
            h = f'HTTP/1.1 200 OK\r\n'
        elif code == 404:
            h = f'HTTP/1.1 404 Not Found\r\n'
        elif code == 405:
            h = f'HTTP/1.1 405 Method Not Allowed\r\n'

        # write further headers
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        h += 'Date: ' + current_date + '\r\n'
        h += 'Server: Simple-Python-HTTP-Server\r\n'
        h += 'Connection: close\r\n'  # signal that the conection will be closed after complting the request
        h += f'Content-Length: {content_length}\r\n'
        h += f'Content-Type: {content_type}\n\n'

        return h

    def wrap_response(self, status: int, html: bytes, content_type='text/html', is_head=False):
        headers = self._gen_headers(status, len(html), content_type)
        response = headers.encode() + html if not is_head else headers.encode()
        print(response)
        return response

    def get_content_type(self, path: str):
        ctypes = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'text/javascript',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.swf': 'application/x-shockwave-flash',
        }
        for ext, mtype in ctypes.items():
            if path.endswith(ext):
                return mtype
        return ctypes['.html']

    def get_response(self, data):
        headers, error = self._get_headers(data)
        if error:
            status, text = error
            return self.wrap_response(status, HTML_ERROR.format(status=status, text=text).encode())
        path = self.resolve_path(headers['path'])
        content_type = self.get_content_type(path)
        html = self.get_html_from_path(path)
        print('PATH: ', headers['path'])
        print('HTML: ', html)
        is_head = headers['command'] == 'HEAD'
        return self.wrap_response(OK, html, content_type=content_type, is_head=is_head) if html else \
            self.wrap_response(NOT_FOUND, HTML_ERROR.format(status=NOT_FOUND, text='Page not found').encode(), is_head=is_head)


if __name__ == '__main__':
    print ("Starting web server")
    s = HTTPServer('127.0.0.1', 9999)  # construct server object
    # shut down on ctrl+c
    signal.signal(signal.SIGINT, s.shutdown)
    s.start()  # aquire the socket
