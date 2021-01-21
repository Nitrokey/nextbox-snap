import os
import sys
import re
from pathlib import Path
from functools import wraps
import signal

import shutil
import socket
import urllib.request, urllib.error
import ssl
import json

# append proper (snap) site-packages path
sys.path.append("/snap/nextbox/current/lib/python3.6/site-packages")

from queue import Queue

import psutil
from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response

from nextbox_daemon.utils import get_partitions, error, success, \
    tail, parse_backup_line, local_ip, cleanup_certs

from nextbox_daemon.command_runner import CommandRunner
from nextbox_daemon.consts import *
from nextbox_daemon.config import Config, log
from nextbox_daemon.worker import Worker
from nextbox_daemon.jobs import JobManager, TrustedDomainsJob



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

    response.headers.add('Access-Control-Allow-Credentials', 'true')
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Headers', 'x-csrf-token')
        response.headers.add('Access-Control-Allow-Headers', 'requesttoken')
        response.headers.add('Access-Control-Allow-Methods',
                            'GET, POST, OPTIONS, PUT, PATCH, DELETE')
    if origin:
        response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', request.remote_addr)


    #response.headers.add('Access-Control-Allow-Origin', cfg["config"]["domain"])

    #if not origin:
    #    response.headers.add('Access-Control-Allow-Origin', "192.168.10.129")
    #    response.headers.add('Access-Control-Allow-Origin', "192.168.10.47")

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


@app.route("/system", methods=["POST", "GET"])
@requires_auth
def system_settings():
    if request.method == "GET":
        return success(data={
            "log_lvl": cfg["config"]["log_lvl"],
            "expert_mode": cfg["config"]["expert_mode"]
        })

    elif request.method == "POST":
        pass


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

    out = dict(cfg["config"])
    if backup_proc is None:
        out["running"] = False
        return out

    assert isinstance(backup_proc, CommandRunner)

    backup_proc.get_new_output()

    if backup_proc.finished:
        if backup_proc.returncode == 0:
            backup_proc.parsed["state"] = "finished"

            cfg["config"]["last_" + backup_proc.user_info] = backup_proc.started
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
    data = dict(cfg["config"])
    data["operation"] = check_for_backup_process()
    data["found"] = []

    if get_partitions()["backup"] is not None:
        for name in os.listdir("/media/backup"):
            p = Path("/media/backup") / name
            try:
                size =  (p / "size").open().read().strip().split()[0]
            except FileNotFoundError:
                continue

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
        output = [x for x in cr.output if x]
        return success(data={
            "service": name,
            "operation": operation,
            "return-code": cr.returncode,
            "output": output
        })
    return error("not allowed")


@app.route("/config", methods=["POST", "GET"])
@requires_auth
def handle_config():
    if request.method == "GET":
        data = dict(cfg["config"])
        data["conf"] = Path(DDCLIENT_CONFIG_PATH).read_text("utf-8").split("\n")
        return success(data=data)

    # save dyndns related values to configuration
    elif request.method == "POST":
        for key in request.form:
            val = request.form.get(key)
            if key == "conf":
                old_conf = Path(DDCLIENT_CONFIG_PATH).read_text("utf-8")
                if old_conf != val:
                    log.info("writing ddclient config and restarting service")
                    Path(DDCLIENT_CONFIG_PATH).write_text(val, "utf-8")
                    service_operation("ddclient", "restart")

            elif key in DYNDNS_CONFIGS and val is not None:
                if key == "dns_mode" and val not in DYNDNS_MODES:
                    log.warning(f"key: 'dns_mode' has invalid value: {val} - skipping")
                    continue
                elif key == "domain":
                    job_queue.put("TrustedDomains")
                elif val is None:
                    log.debug(f"skipping key: '{key}' -> no value provided")
                    continue

                cfg["config"][key] = val
                log.debug(f"saving key: '{key}' with value: '{val}'")
                cfg.save()

        return success("DynDNS configuration saved")


@app.route("/dyndns/captcha", methods=["POST"])
@requires_auth
def dyndns_captcha():
    req = urllib.request.Request(DYNDNS_DESEC_CAPTCHA, method="POST")
    data = urllib.request.urlopen(req).read().decode("utf-8")
    return success(data=json.loads(data))

@app.route("/dyndns/register", methods=["POST"])
@requires_auth
def dyndns_register():
    data = {}
    for key in request.form:
        if key == "captcha_id":
            data.setdefault("captcha", {})["id"] = request.form.get(key)
        elif key == "captcha":
            data.setdefault("captcha", {})["solution"] = request.form.get(key)
        elif key in ["domain", "email"]:
            data[key] = request.form.get(key)
    data["password"] = None

    headers = {"Content-Type": "application/json"}

    req = urllib.request.Request(DYNDNS_DESEC_REGISTER,
        method="POST", data=json.dumps(data).encode("utf-8"), headers=headers)

    try:
        res = urllib.request.urlopen(req).read().decode("utf-8")
    except urllib.error.HTTPError as e:
        desc = e.read()
        return error(f"Could not complete registration", data=json.loads(desc))
    return success(data=json.loads(res))

@app.route("/dyndns/test/ddclient")
@requires_auth
def test_ddclient():
    cr = CommandRunner([DDCLIENT_BIN, "-verbose", "-foreground", "-force"], block=True)
    cr.log_output()

    for line in cr.output:
        if "SUCCESS:" in line:
            return success("DDClient test: OK")
        if "Request was throttled" in line:
            pat = "available in ([0-9]*) seconds"
            try:
                waitfor = int(re.search(pat, line).groups()[0]) + 5
            except:
                waitfor = 10
            return error("DDClient test: Not OK",
                data={"reason": "throttled", "waitfor": waitfor})

    return error("DDClient test: Not OK", data={"reason": "unknown"})

@app.route("/dyndns/test/resolve")
@requires_auth
def test_resolve():
    domain = cfg["config"]["domain"]
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
        return error("Resolve test: Not OK, check logs...", data={"ip": ext_ip})

    return success("Resolve test: OK", data={"ip": ext_ip})

@app.route("/dyndns/test/http")
@app.route("/dyndns/test/https")
@requires_auth
def test_http():
    what = request.path.split("/")[-1]
    domain = cfg["config"]["domain"]
    url = f"{what}://{domain}"
    try:
        content = urllib.request.urlopen(url).read().decode("utf-8")
    except urllib.error.URLError as e:
        return error(f"Domain ({what}) test: Not OK",
                     data={"exc": repr(e)})
    except ssl.CertificateError as e:
        # this very likely is due to a bad certificate, disabling https
        # @TODO: handle this case in frontend
        return error(f"Domain ({what}) test: Not OK - Certificate Error",
                     data={"reason": "cert", "exc": repr(e)})

    if "Nextcloud" in content:
        return success(f"Domain ({what}) test: OK")
    else:
        return error(f"Domain ({what}) test: Not OK",
                     data={"exc": "none", "reason": "no Nextcloud in 'content'"})

@app.route("/dyndns/upnp")
@requires_auth
def setup_upnp():
    import netifaces
    import upnpclient

    # get gateway ip
    gw_ip = list(netifaces.gateways()['default'].values())[0][0]
    # get devices (long operation)
    devs = upnpclient.discover(timeout=0.1)
    device = None
    # filter out gateway
    for dev in devs:
        if dev._url_base.startswith(f"http://{gw_ip}"):
            device = dev
            break

    if device is None:
        return error("cannot find upnp-capable router")

    # check for needed service
    service = None
    for srv in device.services:
        if srv.name == "WANIPConn1":
            service = srv
            break

    if service is None:
        return error("found upnp-capable router - but w/o the needed service")

    eth_ip = local_ip()

    http_args = dict(NewRemoteHost='0.0.0.0', NewExternalPort=80,
         NewProtocol='TCP', NewInternalPort=80, NewInternalClient=eth_ip,
         NewEnabled='1', NewPortMappingDescription='NextBox - HTTP', NewLeaseDuration=0)
    https_args = dict(NewRemoteHost='0.0.0.0', NewExternalPort=443,
         NewProtocol='TCP', NewInternalPort=443, NewInternalClient=eth_ip,
         NewEnabled='1', NewPortMappingDescription='NextBox - HTTPS',
         NewLeaseDuration=0)
    service.AddPortMapping(**http_args)
    service.AddPortMapping(**https_args)

    try:
        service.GetSpecificPortMappingEntry(**http_args)
        service.GetSpecificPortMappingEntry(**https_args)
    except upnpclient.soap.SOAPError as e:
        return error("failed setting up port-forwarding")
    return success("port-forwarding successfully set up")


@app.route("/https/enable", methods=["POST"])
@requires_auth
def https_enable():
    cleanup_certs()

    domain = cfg.get("config", {}).get("domain")
    email = cfg.get("config", {}).get("email")
    if not domain or not email:
        return error(f"failed, domain: '{domain}' email: '{email}'")

    cmd = [ENABLE_HTTPS_BIN, "lets-encrypt", email, domain]
    cr = CommandRunner(cmd, block=True)
    cr.log_output()

    cfg["config"]["https_port"] = 443
    cfg.save()

    return success("HTTPS enabled")

@app.route("/https/disable", methods=["POST"])
@requires_auth
def https_disable():
    cmd = [DISABLE_HTTPS_BIN]
    cr = CommandRunner(cmd, block=True)
    cr.log_output()

    cfg["config"]["https_port"] = None
    cfg.save()

    cleanup_certs()

    return success("HTTPS disabled")


def signal_handler(signal, frame):
    print("Exit handler, delivering worker exit job now")
    job_queue.put("exit")
    w.join()
    print("Joined worker - exiting now...")

    sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    job_mgr = JobManager(cfg)
    job_mgr.register_job(TrustedDomainsJob())

    job_queue = Queue()
    w = Worker(job_queue, job_mgr)
    w.start()

    app.run(host="0.0.0.0", port=18585, debug=True, threaded=True, processes=1)

