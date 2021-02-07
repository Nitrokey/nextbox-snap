from datetime import datetime as dt
from time import sleep

import psutil

from nextbox_daemon.consts import *
from nextbox_daemon.command_runner import CommandRunner
from nextbox_daemon.config import log
from nextbox_daemon.snapd import SnapsManager

class BaseJob:
    name = None
    interval = None

    def __init__(self):
        self.last_run = dt.now()

    def is_due(self):
        if self.interval is None:
            return False
        return (dt.now() - self.last_run).seconds > self.interval

    def run(self, cfg):
        log.debug(f"starting worker job: {self.name}")
        self.last_run = dt.now()
        self._run(cfg)
        log.debug(f"finished worker job: {self.name}")

    def _run(self, cfg):
        raise NotImplementedError()


class UpdateJob(BaseJob):
    name = "UpdateJob"
    interval = 11

    def __init__(self):
        self.snap_mgr = SnapsManager()
        super().__init__()

    def _run(self, cfg):
        log.debug("checking for needed refresh")
        updated = self.snap_mgr.check_and_refresh()

        if "nextbox" in updated:
            while not self.snap_mgr.is_change_done():
                sleep(1)
                log.debug("waiting for snap refresh jobs to be done")
            CommandRunner([SYSTEMCTL_BIN, "restart", NEXTBOX_SERVICE], block=True)
            log.info("restarted nextbox-daemon due to update")

        cr1 = CommandRunner(UPDATE_NEXTBOX_APP_CMD, block=True)
        if cr1.returncode != 0:
            cr2 = CommandRunner(INSTALL_NEXTBOX_APP_CMD, block=True)
            log.info("installed nextbox nextcloud app - wasn't found for update")


class ProxySSHJob(BaseJob):
    name = "ProxySSH"
    interval = 291

    # ssh-keygen -b 4096 -t rsa -f /tmp/sshkey -q -N ""
    # ssh -p 2215 -n -N -i hello_key -R 43022:localhost:80 nbproxy@mate.nitrokey.com

    ssh_cmd = "ssh -p {ssh_port} -f -N -i {key_path} -R {remote_port}:localhost:{local_port} {host}"

    def __init__(self):
        self.pid = None
        super().__init__()

    def _run(self, cfg):
        data = {
            "ssh_port": 2215,
            "key_path": "/var/snap/nextbox/current/hello_key",
            "remote_port": 43022,
            "local_port": 80,
            "host": "nbproxy@mate.nitrokey.com",
        }

        # do nothing except killing process, if proxy_active == False
        if not cfg["config"]["proxy_active"]:
            if self.pid and psutil.pid_exists(self.pid):
                psutil.Process(self.pid).kill()
            self.pid = None
            return

        if not cfg["config"]["nk_token"]:
            log.error("cannot establish reverse proxy - no token")
            return

        if self.pid is not None:
            if not psutil.pid_exists(self.pid):
                self.pid = None
                log.warning("missing reverse proxy process, restarting")

        # no running reverse proxy connection, establish!
        if self.pid is None:
            log.info("Starting reverse proxy connection")
            cmd = self.ssh_cmd.format(**data).split(" ")
            cr = CommandRunner(cmd, block=True)
            if cr.returncode == 0:
                # searching for process, as daemonizing leads to new pid
                for proc in psutil.process_iter():
                    if proc.name() == "ssh":
                        self.pid = proc.pid
                        break
                log.info(f"Success starting reverse proxy (pid: {self.pid})")
            else:
                cr.log_output()
                log.error("Failed starting reverse proxy, check configuration")

class TrustedDomainsJob(BaseJob):
    name = "TrustedDomains"
    interval = 471

    static_entries = ["192.168.*.*", "10.*.*.*", "172.16.*.*"]

    def _run(self, cfg):
        # my_ip = local_ip()

        get_cmd = lambda prop: [OCC_BIN, "config:system:get", prop]
        set_cmd = lambda prop, idx, val: \
            [OCC_BIN, "config:system:set", prop, str(idx), "--value", val]

        cr = CommandRunner(get_cmd("trusted_domains"), block=True)
        trusted_domains = [line.strip() for line in cr.output if len(line.strip()) > 0]
        cr = CommandRunner(get_cmd("proxy_domains"), block=True)
        proxy_domains = [line.strip() for line in cr.output if len(line.strip()) > 0]

        # leave 0-th entry as it is all the time: worst-case fallback

        # check if any static entries are missing
        if any(entry not in trusted_domains for entry in self.static_entries):
            for idx, entry in enumerate(self.static_entries):
                log.info(f"adding '{entry}' to 'trusted_domains' with idx: {idx+1}")
                cr = CommandRunner(set_cmd("trusted_domains", idx+1, entry), block=True)
                if cr.returncode != 0:
                    log.warning(f"failed: {cr.info()}")

        # check for dynamic domain, set to idx == len(static) + 1
        dyn_dom = cfg.get("config", {}).get("domain")
        idx = len(self.static_entries) + 1
        if dyn_dom is not None and dyn_dom not in trusted_domains:
            log.info(f"updating 'trusted_domains' with dynamic domain: '{dyn_dom}'")
            cr = CommandRunner(set_cmd(idx, dyn_dom),
                               block=True)
            if cr.returncode != 0:
                log.warning(f"failed adding domain ({dyn_dom}) to trusted_domains")

        # check and set proxy domain, set to idx == 1
        proxy_dom = cfg.get("config", {}).get("proxy_domain")
        if proxy_dom and cfg.get("config", {}).get("proxy_active"):
            idx = 1
            if proxy_dom is not None and proxy_dom not in proxy_domains:
                log.info(
                    f"updating 'proxy_domains' with proxy domain: '{proxy_dom}'")
                cr = CommandRunner(set_cmd(idx, proxy_dom), block=True)
                if cr.returncode != 0:
                    log.warning(
                        f"failed adding domain ({proxy_dom}) to proxy_domains")


class JobManager:
    def __init__(self, config):
        self.cfg = config
        self.jobs = { }

    def register_job(self, job):
        log.info(f"registering job {job.name}")
        if job.name in self.jobs:
            log.warning(f"overwriting job (during register) with name: {job.name}")
        self.jobs[job.name] = job()


    def handle_job(self, job_name):
        if job_name not in self.jobs:
            log.error(f"could not find job with name: {job_name}")
            return

        # run actual job
        try:
            self.jobs[job_name].run(self.cfg)
        except Exception as e:
            log.error(f"failed running job: {job_name}")
            log.error(exc_info=e)

    def get_recurring_job(self):
        for name, job in self.jobs.items():
            if job.is_due():
                return name

