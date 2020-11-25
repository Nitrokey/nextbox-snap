
from queue import Empty
from threading import Thread
from time import sleep


class JobManager:
    def handle_job(self, job):
        pass

    def get_recurring_job(self):
        return None



class Worker(Thread):
    def __init__(self, job_queue, *v, **kw):
        super().__init__(*v, **kw)

        self.my_job_queue = job_queue
        self.job_mgr = JobManager()

    def run(self):
        while True:
            try:
                job = self.my_job_queue.get(timeout=30)
            except Empty:
                job = self.job_mgr.get_recurring_job()

            if job is None:
                sleep(1)
                continue

            self.job_mgr.handle_job(job)



