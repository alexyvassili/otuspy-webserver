import socket
import threading
import string
import random
import sys
import signal
import logging
import time
import os
from urllib import parse
import argparse
from collections import defaultdict

LOGGING_FORMAT = '[%(asctime)s] %(levelname).1s %(message)s'
LOGGING_LEVEL = logging.INFO
LOGGING_FILE = None

logging.basicConfig(format=LOGGING_FORMAT, datefmt='%Y.%m.%d %H:%M:%S', level=LOGGING_LEVEL,
                            filename=LOGGING_FILE)

HOST = '127.0.0.1'
PORT = 8080
DOCUMENT_ROOT = 'www'

OK = 200
NOT_FOUND = 404
FORBIDDEN = 403
BAD_REQUEST = 400
NOT_ALLOWED = 405
INTERNAL_SERVER_ERROR = 500
HTTP_VERSION_NOT_SUPPORTED = 505
HTML_ERROR = """<html>
<head>
<meta charset="UTF-8"> 
<title>{status} - {text}</title>
</head>
<body>
<h1>¯\_(ツ)_/¯</h1>
<h2>{status}</h2>
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
    def __init__(self, host, port, workers):
        self.host = host
        self.port = port
        self.read_size = 1024
        self.workers = workers
        self.opened_threads = []
        self.closed_threads = []
        self.subthreads_owners = defaultdict(list)

    def start(self):
        """ Attempts to aquire the socket and launch the server """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            logging.info(f"Launching HTTP server on {self.host} : {self.port}")
            self.sock.bind((self.host, self.port))

        except Exception as e:
            logging.info(f"ERROR: Failed to acquire sockets for port {self.port}")
            logging.info("Try running the Server in a privileged user mode.")
            self.shutdown()
            import sys
            sys.exit(1)

        logging.info(f"Server successfully acquired the socket with port: {self.port}")
        logging.info("Press Ctrl+C to shut down the server and exit.")
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            logging.debug('STARTING WORKERS')
            for _ in range(self.workers):
                key = self._get_key()
                worker_key = f'WORKER_{key}'
                logging.info(f'Starting worker with key: {worker_key}')
                executor.submit(self._listen, worker_key)
        logging.debug('WORKERS STARTED')
        #  FIXME почему поток выполнения никогда не достигает этой строчки??
        logging.info("BEHIND WITH")
        # self._listen()

    def _get_key(self):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

    def _listen(self, worker_key):
        self.sock.listen(5)
        while True:
            logging.debug(f'{worker_key}: ACCEPTING')
            client, address = self.sock.accept()
            logging.debug(f'{worker_key}: ADDRESS: {address}')
            logging.debug(f'{worker_key}: SET TIMEOUT')
            client.settimeout(10)
            key = self._get_key()
            logging.info(f"{worker_key}: START NEW THREAD WITH KEY {key}")
            threading.Thread(target = self.listen_to_client, args = (client, address,worker_key, key)).start()
            self.opened_threads.append(key)
            self.subthreads_owners[worker_key].append(key)

    def listen_to_client(self, client, address, worker_key,  thread_key):
        logging.debug(f'{worker_key} : THREAD {thread_key} : STARTED NEW THREAD FOR {address}')
        try:
            logging.debug(f'{worker_key} : THREAD {thread_key} : GETTING DATA')
            data = self._read(client)
            logging.debug(f'{worker_key} : THREAD {thread_key} : DATA IS: {data}')
            if data:
                response = self.get_response(data)
                # client.send(response) TODO: как лучше?
                client.sendall(response)
                logging.info(f'{worker_key} : THREAD {thread_key} : RESPONSE SENDED, EXITING')
                client.close()
                self.closed_threads.append(thread_key)
                return True
            else:
                raise socket.error('Client disconnected')
        except OSError as e:
            logging.info(f'{worker_key} : THREAD {thread_key} : CLIENT DISCONNECTED, EXITING')
            client.close()
            self.closed_threads.append(thread_key)
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
            logging.info("Shutting down the server")
            self.sock.shutdown(socket.SHUT_RDWR)

        except Exception as e:
            logging.info(f"Warning: could not shut down the socket. Maybe it was already closed? {e}")
            exit_code = 1

        finally:
            logging.info(f'Opened threads: {len(self.opened_threads)}')
            logging.info(f'Closed threads: {len(self.closed_threads)}')
            logging.info(f'Workers statistic: ')
            for worker, threads in self.subthreads_owners.items():
                logging.info(f'{worker} :: {len(threads)} threads.')
            sys.exit(exit_code)


class HTTPServer(HelloServer):
    def __init__(self, host, port, workers, document_root):
        self.document_root = document_root
        self.delimiter = b'\r\n'
        self.ender = b'\r\n\r\n'
        # в настоящее время на каждое нажатие F5 в браузере сервер создает отдельный тред.
        # и закрытия этих тредов что-то не видно. Есть параметр keep-alive, и вроде как если он есть
        # соединение с этим браузером не должно отдаваться другому треду.
        # непонятно как это реализовать. Пока ощущение, что плодиться куча тредов и они нихрена потом
        # не закрываются нормально.
        # Косвенно на это указывает тот факт, что при апач тесте процесс сервера потихонечку разрастается в памяти.
        # Хотя посчитал статистику - вроде ничего
        # [2018.04.27 17:07:09] I Opened threads: 49967
        # [2018.04.27 17:07:09] I Closed threads: 49961
        # а время на запрос пишет - 10 секунд, значит все запросы отваливаются по таймауту!
        # значит надо закрывать тред после каждого ответа
        # сразу стали запросы по 20 мс выполняться
        # и треды закрываются, но все-таки не все:
        # [2018.04.27 17: 34:47] I Opened threads: 49910
        # [2018.04.27 17:34:47] I Closed threads: 49902

        # кстати если убрать Thread Pool - то сервер при закрытии вообще будет зависать,
        # по-крайней мере из пайчарма так.
        # Сейчас получается что у меня воркер треды, которые создают еще треды.
        # Нормально ли это вообще? :)
        # Еще сервак тормозит на тесте HEAD - видимо ждет конца пакета?
        # непонятно, что ему нужно отдавать. Или Content-Length = 0 писать?
        self.close_connection = True
        super().__init__(host, port, workers)

    def _read(self, client):
        maxsize = 65536
        data = bytearray()
        while self.ender not in data:
            data += client.recv(self.read_size)
            if len(data) > maxsize:
                raise TypeError('HTTP request is too big')  # TODO: ERROR 400
        return data

    def _get_headers(self, data):
        """Only \r\n delimiter syntax is supported ¯\_(ツ)_/¯
           returns tuple:
                headers: dict (empty if error while parsing headers
                error: tuple(error_code, error_str) (empty if parsed without an error)
        """
        headers = dict()
        headersline = str(data, 'iso-8859-1')
        headersline = headersline.rstrip('\r\n')
        headerslist = headersline.split('\r\n')
        try:
            firstline, add_headers = headerslist[0], headerslist[1:]
            words = firstline.split()
        except Exception as e:
            return dict(), (BAD_REQUEST, "Bad request syntax (%r)" % headersline)
        command, path, version = '', '', ''
        if len(words) == 3:
            command, path, version = words
        elif len(words) == 2:
            command, path = words

        headers['command'] = command
        headers['path'] = path
        headers['version'] = version
        for line in add_headers:
            key, value = line.split(': ')
            headers[key] = value
        logging.debug(f'HEADERS: {headers}')

        if headers['version']:
            version = headers['version']
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
        if headers['command'] not in ['GET', 'HEAD']:
            return dict(), (NOT_ALLOWED, "Method not allowed: (%r)" % headers['command'])
        # conntype = headers.get('Connection', "")
        # if conntype.lower() == 'close':
        #     self.close_connection = True
        # elif (conntype.lower() == 'keep-alive' and
        #       headers['version'] >= "HTTP/1.1"):
        #     self.close_connection = False
        return headers, tuple()

    def get_html_from_path(self, path):
        html = b''
        try:
            logging.debug(f'TRY OPEN FILE: {path}')
            with open(path, 'rb') as f:
                html = f.read()
        except Exception as e:
            logging.debug("EXCEPTION")
            logging.debug(e.args)  # TODO: DEBUG MODE

        return html

    def resolve_path(self, path: str) -> tuple:
        logging.debug(f'PATH GETTED {path}')
        query = ''
        if '?' in path:
            path, query = path.split('?')
        if '../' in path:
            return '', ''
        if '%' in path:
            path = parse.unquote(path)
        if path == '/':
            path = os.path.join(self.document_root, 'index.html')
        else:
            path = self.document_root + path
        if os.path.isdir(path):
            path = os.path.join(path, 'index.html')  # 'htm' extension is not supported
        logging.debug(f'RESOLVED PATH: {path}')
        return path, query

    def _gen_headers(self, code, content_length, content_type):
        """ Generates HTTP response Headers."""

        # determine response code
        h = ''
        # TODO: зарефакторить
        if code == 200:
            h = f'HTTP/1.1 200 OK\r\n'
        elif code == 404:
            h = f'HTTP/1.1 404 Not Found\r\n'
        elif code == 405:
            h = f'HTTP/1.1 405 Method Not Allowed\r\n'
        elif code == 403:
            h = f'HTTP/1.1 403 Forbidden\r\n'
        else:
            raise ValueError(f'Unexpected response code: {code}')

        # write further headers
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        h += 'Date: ' + current_date + '\r\n'
        h += 'Server: Simple-Python-HTTP-Server\r\n'
        h += 'Connection: close\r\n'  # signal that the conection will be closed after compliting the request
        h += f'Content-Length: {content_length}\r\n'
        h += f'Content-Type: {content_type}\n\n'

        return h

    def wrap_response(self, status: int, html: bytes, content_type='text/html', is_head=False):
        headers = self._gen_headers(status, len(html), content_type)
        response = headers.encode() + html if not is_head else headers.encode() + b'\r\n\r\n'
        logging.debug(f'RESPONSE HEADERS IS: {headers}')
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
        path, query = self.resolve_path(headers['path'])
        content_type = self.get_content_type(path)
        html = self.get_html_from_path(path)
        is_head = headers['command'] == 'HEAD'
        if html:
            return self.wrap_response(OK, html, content_type=content_type, is_head=is_head)
        elif not html and 'index.html' in path:
            return self.wrap_response(FORBIDDEN, HTML_ERROR.format(status=FORBIDDEN, text='Forbidden').encode(),
                                   is_head=is_head)
        else:
            return self.wrap_response(NOT_FOUND, HTML_ERROR.format(status=NOT_FOUND, text='Page not found').encode(),
                                      is_head=is_head)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', default=HOST)
    parser.add_argument('-p', '--port', default=PORT, type=int)
    parser.add_argument('-w', '--workers', default=4, type=int)
    parser.add_argument('-r', '--documentroot', default=DOCUMENT_ROOT)
    return parser


def get_config() -> dict:
    parser = create_parser()
    namespace = parser.parse_args()
    return {
        'host': namespace.ip,
        'port': namespace.port,
        'workers': namespace.workers,
        'document_root': namespace.documentroot,
    }


if __name__ == '__main__':
    config = get_config()
    logging.info ("Starting web server")
    server = HTTPServer(**config)  # construct server object
    # shut down on ctrl+c
    signal.signal(signal.SIGINT, server.shutdown)
    server.start()  # aquire the socket
