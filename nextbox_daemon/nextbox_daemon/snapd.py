import requests
import socket
import pprint

from urllib.connection import HTTPConnection
from urllib.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter


class SnapdConnection(HTTPConnection):
    def __init__(self):
        super().__init__("localhost")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/snapd.socket")


class SnapdConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super().__init__("localhost")

    def _new_conn(self):
        return SnapdConnection()


class SnapdAdapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return SnapdConnectionPool()


session = requests.Session()
session.mount("http://snapd/", SnapdAdapter())
response = session.get("http://snapd/v2/system-info")
pprint.pprint(response.json())