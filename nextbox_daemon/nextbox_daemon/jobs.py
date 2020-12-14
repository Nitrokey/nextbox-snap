from datetime import datetime as dt

from nextbox_daemon.consts import OCC_BIN
from nextbox_daemon.command_runner import CommandRunner
from nextbox_daemon.config import log


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


class TrustedDomainsJob(BaseJob):
    name = "TrustedDomains"
    interval = 30

    static_entries = ["192.168.*.*", "10.*.*.*", "172.16.*.*"]

    def _run(self, cfg):
        # my_ip = local_ip()

        get_cmd = lambda: [OCC_BIN, "config:system:get", "trusted_domains"]
        set_cmd = lambda idx, val: \
            [OCC_BIN, "config:system:set", "trusted_domains", str(idx), "--value", val]

        cr = CommandRunner(get_cmd(), block=True)
        trusted_domains = [line.strip() for line in cr.output if len(line.strip()) > 0]

        # leave 0-th entry as it is all the time: worst-case fallback

        # check if any static entries are missing
        if any(entry not in trusted_domains for entry in self.static_entries):
            for idx, entry in enumerate(self.static_entries):
                log.info(f"adding '{entry}' to 'trusted_domains' with idx: {idx+1}")
                cr = CommandRunner(set_cmd(idx+1, entry), block=True)

                if cr.returncode != 0:
                    log.warning(f"failed: {cr.info()}")

        # now check for dynamic domain, always add this after the static entries idx
        dyn_dom = cfg.get("nextcloud", {}).get("domain")
        if dyn_dom is not None and dyn_dom not in trusted_domains:
            log.info(f"updating 'trusted_domains' with dynamic domain: '{dyn_dom}'")
            cr = CommandRunner(set_cmd(len(self.static_entries)+1, dyn_dom), block=True)
            if cr.returncode != 0:
                log.warning(f"failed adding domain ({dyn_dom}) to trusted_domains")



class JobManager:
    def __init__(self, config):
        self.cfg = config
        self.jobs = { }

    def register_job(self, job):
        log.info(f"registering job {job.name}")
        if job.name in self.jobs:
            log.warning(f"overwriting job (during register) with name: {job.name}")
        self.jobs[job.name] = job


    def handle_job(self, job_name):
        if job_name not in self.jobs:
            log.error(f"could not find job with name: {job_name}")

        # run actual job
        self.jobs[job_name].run(self.cfg)

    def get_recurring_job(self):
        for name, job in self.jobs.items():
            if job.is_due():
                return name

