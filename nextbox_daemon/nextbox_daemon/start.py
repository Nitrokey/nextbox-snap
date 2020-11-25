import os
import sys
from pathlib import Path
from functools import wraps

import select
import time
import threading
import subprocess

import shutil
import socket
import urllib.request

# append proper (snap) site-packages path
sys.path.append("/snap/nextbox/current/lib/python3.6/site-packages")

import logging
import logging.handlers

from queue import Queue

import psutil
from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response

from nextbox_daemon.utils import get_partitions, error, success, \
    tail, parse_backup_line, local_ip

from nextbox_daemon.command_runner import CommandRunner
from nextbox_daemon.consts import *
from nextbox_daemon.config import Config
from nextbox_daemon.worker import Worker



# logger setup + rotating file handler
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)
log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILENAME, maxBytes=MAX_LOG_SIZE, backupCount=5)
log.addHandler(log_handler)
log_format = logging.Formatter("{asctime} {module} {levelname} => {message}", style='{')
log_handler.setFormatter(log_format)

log.info("starting nextbox-daemon")


# config load
cfg = Config(CONFIG_PATH)

app = Flask(__name__)
app.secret_key = "123456-nextbox-123456" #cfg["secret_key"]

# backup thread handler
backup_proc = None

#@app.before_request
#def limit_remote_addr():
#    if request.remote_addr != '10.20.30.40':
#        abort(403)  # Forbidden
#

### CORS section
@app.after_request
def after_request_func(response):
    origin = request.headers.get('Origin')
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Headers', 'x-csrf-token')
        response.headers.add('Access-Control-Allow-Methods',
                            'GET, POST, OPTIONS, PUT, PATCH, DELETE')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)

    if not origin:
        response.headers.add('Access-Control-Allow-Origin', "192.168.10.129")

    return response
### end CORS section



# decorator for authenticated access
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.remote_addr != "127.0.0.1":
            # abort(403)
            return error("not allowed")

        return f(*args, **kwargs)
    return decorated


@app.route("/overview")
def show_overview():
    return success(data={
        "storage": get_partitions(),
        "backup": check_for_backup_process()
    })


@app.route("/log")
@app.route("/log/<num_lines>")
@requires_auth
def show_log(num_lines=50):
    ret = tail(LOG_FILENAME, num_lines)
    return error(f"could not read log: {LOG_FILENAME}") if ret is None \
        else success(data=ret[:-1])


#
# @app.route("/token/<token>/<allow_ip>")
# def set_token(token, allow_ip):
#
#     if request.remote_addr != "127.0.0.1":
#         #abort(403)
#         return error("not allowed")
#
#     cfg["token"]["value"] = token
#     cfg["token"]["created"] = time.time()
#     cfg["token"]["ip"] = allow_ip
#     save_config(cfg, CONFIG_PATH)
#
#     return success()


@app.route("/storage")
@requires_auth
def storage():
    parts = get_partitions()
    return success(data=parts)


@app.route("/storage/mount/<device>")
@app.route("/storage/mount/<device>/<name>")
@requires_auth
def mount_storage(device, name=None):
    parts = get_partitions()

    if name is None:
        print (parts)
        for idx in range(1, 11):
            _name = f"extra-{idx}"
            mount_target = f"/media/{_name}"
            if mount_target not in parts["mounted"].values():
                name = _name
                print(name)
                break

        if name is None:
            return error("cannot determine mount target, too many mounts?")

    if ".." in device or "/" in device or name == "nextcloud":
        return error("invalid device")
    if ".." in name or "/" in name:
        return error("invalid name")

    mount_target = f"/media/{name}"
    mount_device = None
    for avail in parts["available"]:
        if Path(avail).name == device:
            mount_device = avail

    if not mount_device:
        return error("device to mount not found")

    if mount_device == parts["main"]:
        return error("will not mount main data partition")

    if mount_device in parts["mounted"]:
        return error("already mounted")

    if mount_target in parts["mounted"].values():
        return error(f"target {mount_target} has been already mounted")

    if not os.path.exists(mount_target):
        os.makedirs(mount_target)

    cr = CommandRunner([MOUNT_BIN, mount_device, mount_target], block=True)
    if cr.returncode == 0:
        return success("Mounting successful", data=cr.output)
    else:
        cr.log_output()
        return error("Failed mounting, check logs...")

@app.route("/storage/umount/<name>")
@requires_auth
def umount_storage(name):
    if ".." in name or "/" in name or name == "nextcloud":
        return error("invalid name")

    mount_target = f"/media/{name}"
    parts = get_partitions()

    if name == "nextcloud":
        return error("will not umount main data partition")

    if mount_target not in parts["mounted"].values():
        return error("not mounted")

    cr = CommandRunner([UMOUNT_BIN, mount_target], block=True)
    return success("Unmounting successful", data=cr.output)

def check_for_backup_process():
    global backup_proc

    out = dict(cfg["backup"])
    if backup_proc is None:
        out["running"] = False
        return out

    assert isinstance(backup_proc, CommandRunner)

    backup_proc.get_new_output()

    if backup_proc.finished:
        if backup_proc.returncode == 0:
            backup_proc.parsed["state"] = "finished"

            cfg["backup"]["last_" + backup_proc.user_info] = backup_proc.started
            cfg.save()


            out["last_" + backup_proc.user_info] = backup_proc.started
            log.info("backup/restore process finished successfully")
        else:
            backup_proc.parsed["state"] = "failed: " + backup_proc.parsed.get("unable", "")
            if "target" in backup_proc.parsed:
                if os.path.exists(backup_proc.parsed["target"]):
                    shutil.rmtree(backup_proc.parsed["target"])
                log.error("backup/restore process failed, logging output: ")
                for line in backup_proc.output[-30:]:
                    log.error(line.replace("\n", ""))


    out.update(dict(backup_proc.parsed))
    out["returncode"] = backup_proc.returncode
    out["running"] = backup_proc.running
    out["what"] = backup_proc.user_info

    if backup_proc.finished:
        backup_proc = None

    return out


@app.route("/backup")
@requires_auth
def backup():
    data = dict(cfg["backup"])
    data["operation"] = check_for_backup_process()
    data["found"] = []

    if get_partitions()["backup"] is not None:
        for name in os.listdir("/media/backup"):
            p = Path("/media/backup") / name
            try:
                size =  (p / "size").open().read().strip().split()[0]
            except FileNotFoundError:
                size = 0

            data["found"].append({
                "name": name,
                "created": p.stat().st_ctime,
                "size": size
            })
            data["found"].sort(key=lambda x: x["created"], reverse=True)

    return success(data=data)


#@app.route("/backup/cancel")
#def backup_cancel(name):
#    global backup_proc
#
#    subprocess.check_call(["killall", "nextcloud-nextbox.export"])
#    #subprocess.check_call(["killall", "nextcloud-nextbox.import"])
#
#    pass


@app.route("/backup/start")
@requires_auth
def backup_start():
    global backup_proc
    backup_info = check_for_backup_process()
    parts = get_partitions()

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    if not parts["backup"]:
        return error("no 'backup' storage mounted")

    backup_proc = CommandRunner([BACKUP_EXPORT_BIN],
        cb_parse=parse_backup_line, block=False)
    backup_proc.user_info = "backup"

    return success("backup started", data=backup_info)


@app.route("/backup/restore/<name>")
@requires_auth
def backup_restore(name):
    global backup_proc
    backup_info = check_for_backup_process()

    if ".." in name or "/" in name:
        return error("invalid name", data=backup_info)

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    directory = f"/media/backup/{name}"
    backup_proc = CommandRunner([BACKUP_IMPORT_BIN, directory],
        cb_parse=parse_backup_line, block=False)
    backup_proc.user_info = "restore"

    return success("restore started", data=backup_info)


@app.route("/service/<name>/<operation>")
@requires_auth
def service_operation(name, operation):
    if name not in ["ddclient"]:
        return error("not allowed")
    if operation not in ["stop", "start", "restart", "status", "is-active"]:
        return error("not allowed")

    if name == "ddclient":
        cr = CommandRunner([SYSTEMCTL_BIN, operation, DDCLIENT_SERVICE], block=True)
        return success(data={
            "service": name,
            "operation": operation,
            "return-code": cr.returncode,
            "output": cr.output
        })
    return error("not allowed")


@app.route("/ddclient/test/ddclient")
@requires_auth
def ddclient_test_ddclient():
    cr = CommandRunner([DDCLIENT_BIN, "-verbose", "-foreground", "-force"], block=True)
    cr.log_output()

    for line in cr.output:
        if "SUCCESS:" in line:
            return success("DDClient test: OK")
    return error("DDClient test: Not OK, check logs...")


@app.route("/ddclient/test/domain")
@requires_auth
def ddclient_test_domain():
    domain = cfg["nextcloud"]["domain"]
    try:
        resolve_ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        log.error(f"Could not resolve {domain}")
        log.error(f"Exception: {e}")
        resolve_ip = None
    ext_ip = urllib.request.urlopen(GET_EXT_IP_URL).read().decode("utf-8")

    log.info(f"resolving '{domain}' to IP: {resolve_ip}, external IP: {ext_ip}")
    if resolve_ip != ext_ip:
        log.warning("Resolved IP does not match external IP")
        log.warning("This might indicate a bad DynDNS configuration")
        return error("Domain test: Not OK, check logs...")

    return success("Domain test: OK")


@app.route("/ddclient/enable")
@requires_auth
def https_enable():
    domain = cfg.get("nextcloud", {}).get("domain")
    email = cfg.get("nextcloud", {}).get("email")
    if not domain or not email:
        return error(f"failed, domain: '{domain}' email: '{email}'")

    cmd = [ENABLE_HTTPS_BIN, "lets-encrypt", email, domain]
    cr = CommandRunner(cmd, block=True)
    cr.log_output()

    cfg["nextcloud"]["https_port"] = 443
    cfg.save()

    return success("HTTPS successfully activated")

@app.route("/ddclient/disable")
@requires_auth
def https_disable():
    cmd = [DISABLE_HTTPS_BIN]
    cr = CommandRunner(cmd, block=True)
    cr.log_output()

    cfg["nextcloud"]["https_port"] = None
    cfg.save()

    # remove any certificates in live dir
    bak = Path(CERTBOT_BACKUP_PATH)
    src = Path(CERTBOT_CERTS_PATH)
    if not bak.exists():
        os.makedirs(bak.as_posix())
        log.debug(f"creating certs backup directory: {bak}")

    contents = os.listdir(src.as_posix())
    if len(contents) > 1:
        log.debug("need to clean up certs directory")

    for path in contents:
        if path == "README":
            continue

        full_src_path = src / path
        full_bak_path = bak / path
        idx = 1
        while full_bak_path.exists():
            full_bak_path = Path((bak / path).as_posix() + f".{idx}")
            idx += 1

        log.debug(f"moving old cert: {full_src_path} to {full_bak_path}")
        shutil.move(full_src_path, full_bak_path)


    return success("HTTPS disabled")

@app.route("/ddclient/config", methods=["POST", "GET"])
@requires_auth
def ddclient_config():
    if request.method == "GET":
        data = dict(cfg["nextcloud"])
        data["conf"] = Path(DDCLIENT_CONFIG_PATH).read_text("utf-8").split("\n")
        return success(data=data)

    elif request.method == "POST":
        for key in request.form:
            val = request.form.get(key)
            if key == "conf":
                old_conf = Path(DDCLIENT_CONFIG_PATH).read_text("utf-8")
                if old_conf != val:
                    log.info("writing changed ddclient config and restarting service")
                    Path(DDCLIENT_CONFIG_PATH).write_text(val, "utf-8")
                    service_operation("ddclient", "restart")

            elif key == "domain" and len(request.form.get(key, "")) > 0:
                cfg["nextcloud"]["domain"] = val
                update_trusted_domains(cfg["nextcloud"]["domain"])
            elif key == "email" and len(request.form.get(key, "")) > 0:
                cfg["nextcloud"]["email"] = val
            cfg.save()

        return success("DDClient configuration saved")


def update_trusted_domains(external_domain=None, force_update=False):
    get_cmd = lambda: [OCC_BIN, "config:system:get", "trusted_domains"]
    my_ip = local_ip()
    set_cmd = lambda idx, val: [OCC_BIN, "config:system:set",
                                "trusted_domains", str(idx), "--value", val]

    cr = CommandRunner(get_cmd(), block=True)
    trusted_domains = [line.strip() for line in cr.output if len(line.strip()) > 0]

    if not my_ip in trusted_domains:
        log.critical(f"LOCAL IP ({my_ip}) NOT IN trusted_domains: {trusted_domains}")

    if external_domain not in trusted_domains:
        # always add at index 1, assuming 0 is the host-ip
        cr = CommandRunner(set_cmd(1, external_domain), block=True)
        cr.log_output()
        # don't forget ... cr.output @fixme
        log.info(f"adding {external_domain} to 'trusted_domains'")


if __name__ == "__main__":

    job_queue = Queue()
    w = Worker(job_queue)
    w.start()

    app.run(host="0.0.0.0", port=18585, debug=True, threaded=True, processes=1)
