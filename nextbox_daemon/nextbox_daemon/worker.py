
from queue import Empty
from threading import Thread
from time import sleep
import logging

from nextbox_daemon.config import log


class Worker(Thread):
    def __init__(self, job_queue, job_mgr, *v, **kw):
        super().__init__(*v, **kw)

        self.my_job_queue = job_queue
        self.job_mgr = job_mgr

    def run(self):
        logging
        while True:
            try:
                job_name = self.my_job_queue.get(timeout=30)
            except Empty:
                job_name = self.job_mgr.get_recurring_job()

            if job_name is None:
                sleep(1)
                continue

            self.job_mgr.handle_job(job_name)



