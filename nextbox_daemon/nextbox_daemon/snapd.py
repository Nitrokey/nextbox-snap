import socket
import pprint

import sys
sys.path.append("/snap/nextbox/current/lib/python3.6/site-packages")

import requests
from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.connection import HTTPConnection

from nextbox_daemon.config import log

# inspired by: https://stackoverflow.com/questions/26964595/whats-the-correct-way-to-use-a-unix-domain-socket-in-requests-framework


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


class SnapsManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.mount("http://snapd/", SnapdAdapter())

        self.running = []

    def get_stable_revision(self, name):
        resp = self.session.get(f"http://snapd/v2/find?name={name}")
        revision = resp.json() \
            .get("result")[0].get("channels").get("latest/stable").get("revision")
        return int(revision)

    def get_local_revision(self, name):
        resp = self.session.get(f"http://snapd/v2/snaps/{name}")
        return int(resp.json().get("result").get("revision"))

    def refresh(self, name):
        data = {
            "action": "refresh",
            "snaps":  [name]
        }
        resp = self.session.post(f"http://snapd/v2/snaps", json=data)
        self.running.append(resp.json().get("change"))
        return resp.get("status") == "OK"

    def is_change_done(self):

        # no running jobs, means all are done
        if len(self.running) == 0:
            return True

        c_id = self.running.pop()
        resp2 = self.session.get(f"http://snapd/v2/changes/{c_id}")
        if resp2.json().get("result").get("status") == "Done":
            return True
        else:
            self.running.append(c_id)
            return False

    def check_and_refresh(self):
        updated = []
        for snap in ["nextbox", "nextcloud-nextbox"]:
            if self.get_stable_revision(snap) != self.get_local_revision(snap):
                self.refresh(snap)
                log.info(f"refreshing: {snap}")
                updated.append(snap)
            else:
                log.debug(f"no need to refresh: {snap}")
        return updated