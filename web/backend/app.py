#!/usr/bin/env python3
import os
import json
import subprocess
import threading
import time
from flask import Flask, request, jsonify, render_template, Response

# Since app.py is inside web/, set static_folder to "static" and template_folder to "templates"
app = Flask(__name__, static_folder="../frontend/static", template_folder="../frontend/templates")

# Calculate BASE_DIR as the parent folder of web/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Directories for EBPF and userspace programs (adjust if needed)
EBPF_SRC_DIR = os.path.join(BASE_DIR, "../ebpf", "src")
USERSPACE_DIR = os.path.join(BASE_DIR, "../userspace")

# Global list and lock for storing collector events (for eBPF)
collected_events = []
events_lock = threading.Lock()

# Global variables for controlling the eBPF collector
collector_started = False
collector_thread = None
collector_proc = None  # Process for the eBPF collector

# Global variables for the userspace program
userspace_proc = None      # Process for the userspace program
userspace_thread = None    # Thread that reads its output
userspace_output = []      # List to store the output lines
userspace_lock = threading.Lock()


def make_absolute_pin_path(pin_path):
    """
    If pin_path is not absolute (does not start with '/'),
    assume it's relative to /sys/fs/bpf.
    """
    if pin_path and not pin_path.startswith("/"):
        return os.path.join("/sys/fs/bpf", pin_path)
    return pin_path


def run_command(cmd):
    """Run a command with sudo and capture output."""
    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        return result.stdout, result.stderr, None
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        return None, None, error_message


def get_loaded_programs():
    """Return loaded eBPF programs with detailed information."""
    cmd = ["bpftool", "prog", "show", "--json"]
    stdout, _, error = run_command(cmd)
    if error:
        app.logger.error(f"[ERROR] bpftool prog show: {error}")
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        app.logger.error(f"[ERROR] JSON decode: {str(e)}")
        return []


# ------------------------
# eBPF Management Endpoints
# ------------------------
@app.route("/")
def home():
    """Serve the advanced UI in index.html."""
    return render_template("index.html")


@app.route("/api/programs", methods=["GET"])
def list_programs():
    """List available and loaded eBPF programs."""
    try:
        programs = [
            f for f in os.listdir(EBPF_SRC_DIR)
            if f.endswith(".o") and os.path.isfile(os.path.join(EBPF_SRC_DIR, f))
        ]
        loaded_programs = get_loaded_programs()
        return jsonify({"programs": programs, "loaded": loaded_programs})
    except Exception as e:
        app.logger.error(f"Failed to list programs: {str(e)}")
        return jsonify({"error": "Failed to list programs"}), 500


@app.route("/api/programs/load", methods=["POST"])
def load_program():
    """Load and pin an eBPF program using bpftool."""
    data = request.get_json() or {}
    program = data.get("program")
    if not program or not program.endswith(".bpf.o"):
        return jsonify({"error": "Invalid or missing 'program' (.bpf.o file required)"}), 400

    program_path = os.path.join(EBPF_SRC_DIR, program)
    if not os.path.isfile(program_path):
        return jsonify({"error": f".o file not found: {program_path}"}), 404

    pin_path = make_absolute_pin_path(data.get("pin_path") or program[:-len(".bpf.o")])
    cmd = ["bpftool", "prog", "loadall", program_path, pin_path]
    _, _, error = run_command(cmd)
    if error:
        return jsonify({"error": f"Failed to load program: {error}"}), 500

    global collector_started
    if not collector_started:
        start_collector()
        collector_started = True
        app.logger.info("Collector started after successful load.")

    with events_lock:
        collected_events.clear()

    return jsonify({"message": f"Program loaded at {pin_path}"}), 200


@app.route("/api/programs/unload", methods=["POST"])
def unload_program():
    """Unload a pinned eBPF program by removing its pin path."""
    data = request.get_json() or {}
    pin_path = data.get("pin_path")
    program = data.get("program")
    if not pin_path and program and program.endswith(".bpf.o"):
        pin_path = make_absolute_pin_path(program[:-len(".bpf.o")])
    if not pin_path or not os.path.isabs(pin_path):
        return jsonify({"error": "Missing or invalid 'pin_path'"}), 400
    if not os.path.exists(pin_path):
        return jsonify({"error": f"Pin path not found: {pin_path}"}), 404
    cmd = ["rm", "-rf", pin_path]
    _, _, error = run_command(cmd)
    if error:
        return jsonify({"error": f"Failed to unload program: {error}"}), 500

    return jsonify({"message": f"Successfully unloaded program at {pin_path}"}), 200


@app.route("/api/programs/attach", methods=["POST"])
def attach_program():
    """Attach a loaded eBPF program to a target using bpftool."""
    data = request.get_json() or {}
    raw_pin_path = data.get("pin_path")
    if not raw_pin_path:
        return jsonify({"error": "Missing 'pin_path' parameter"}), 400

    pin_path = make_absolute_pin_path(raw_pin_path)
    attach_type = data.get("attach_type", "tracepoint")
    if attach_type == "tracepoint":
        target = data.get("target") or "tracepoint/syscalls/sys_enter_execve"
        cmd = ["bpftool", "prog", "attach", "pinned", pin_path, "tracepoint", target]
    elif attach_type == "xdp":
        target = data.get("target") or "eth0"
        cmd = ["bpftool", "net", "attach", "xdp", "dev", target, "pinned", pin_path]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    _, _, error = run_command(cmd)
    if error:
        return jsonify({"error": f"Attach failed: {error}"}), 500

    return jsonify({"message": f"Attached {pin_path} to {attach_type}:{target}"}), 200


@app.route("/api/programs/detach", methods=["POST"])
def detach_program():
    """Detach an attached eBPF program using bpftool."""
    data = request.get_json() or {}
    raw_pin_path = data.get("pin_path")
    if not raw_pin_path:
        return jsonify({"error": "Missing 'pin_path' parameter"}), 400

    pin_path = make_absolute_pin_path(raw_pin_path)
    attach_type = data.get("attach_type")
    target = data.get("target")
    if not attach_type or not target:
        return jsonify({"error": "Missing required parameters: attach_type and target"}), 400

    if attach_type == "tracepoint":
        cmd = ["bpftool", "prog", "detach", "pinned", pin_path, "tracepoint", target]
    elif attach_type == "xdp":
        cmd = ["bpftool", "net", "detach", "xdp", "dev", target]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    _, _, error = run_command(cmd)
    if error:
        return jsonify({"error": f"Detach failed: {error}"}), 500

    return jsonify({"message": f"Detached {pin_path} from {attach_type}:{target}"}), 200


# ------------------------
# Collector Endpoints (for eBPF)
# ------------------------
@app.route("/api/collector_events", methods=["GET"])
def get_collector_events():
    with events_lock:
        events_copy = collected_events.copy()
    return jsonify({"events": events_copy})


@app.route("/api/clear_logs", methods=["POST"])
def clear_logs():
    with events_lock:
        collected_events.clear()
    return jsonify({"message": "Collector logs cleared"}), 200


@app.route("/api/dump_logs", methods=["GET"])
def dump_logs():
    with events_lock:
        log_text = "\n".join(collected_events)
    response = Response(log_text, mimetype="text/plain")
    response.headers["Content-Disposition"] = "attachment;filename=collector_logs.txt"
    return response


@app.route("/api/start_collection", methods=["POST"])
def start_collection_endpoint():
    global collector_started
    if collector_started:
        return jsonify({"message": "Collector process already running."}), 200
    try:
        start_collector()
        collector_started = True
        app.logger.info("Collector process started.")
        return jsonify({"message": "Collector process started."}), 200
    except Exception as ex:
        app.logger.error(f"Failed to start collector: {ex}")
        return jsonify({"error": f"Failed to start collector: {ex}"}), 500


@app.route("/api/stop_collection", methods=["POST"])
def stop_collection():
    global collector_proc, collector_started
    if collector_proc is not None and collector_proc.poll() is None:
        try:
            subprocess.run(["sudo", "kill", "-TERM", str(collector_proc.pid)], check=True)
            collector_proc.wait(timeout=5)
            collector_started = False
            app.logger.info("Collector process terminated successfully.")
            return jsonify({"message": "Collector process stopped."}), 200
        except Exception as ex:
            app.logger.error(f"Failed to stop collector: {ex}")
            return jsonify({"error": f"Failed to stop collector: {ex}"}), 500
    else:
        collector_started = False
        return jsonify({"message": "Collector process is not running."}), 200


def start_collector():
    def run_collector():
        global collector_proc
        try:
            proc = subprocess.Popen(
                ["sudo", "./exec"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            collector_proc = proc
        except Exception as ex:
            app.logger.error(f"Failed to launch collector: {ex}")
            return

        while True:
            line = proc.stdout.readline()
            if line:
                line = line.strip()
                with events_lock:
                    collected_events.append(line)
                app.logger.info(f"Collector event: {line}")
            else:
                if proc.poll() is not None:
                    app.logger.info("Collector process terminated.")
                    break
                time.sleep(0.1)
        proc.stdout.close()
        proc.wait()
        collector_proc = None

    global collector_thread
    collector_thread = threading.Thread(target=run_collector, daemon=True)
    collector_thread.start()


# ------------------------
# Userspace Program Endpoints
# ------------------------
@app.route("/api/userspace_programs", methods=["GET"])
def list_userspace_programs():
    try:
        programs = [
            f for f in os.listdir(USERSPACE_DIR)
            if os.path.isfile(os.path.join(USERSPACE_DIR, f)) and os.access(os.path.join(USERSPACE_DIR, f), os.X_OK)
        ]
        app.logger.info(f"Userspace programs found: {programs}")
        return jsonify({"programs": programs})
    except Exception as ex:
        app.logger.error(f"Failed to list userspace programs: {ex}")
        return jsonify({"error": "Failed to list userspace programs"}), 500


@app.route("/api/start_userspace", methods=["POST"])
def start_userspace():
    data = request.get_json() or {}
    program = data.get("program")
    args = data.get("args", "")
    if not program:
        return jsonify({"error": "Missing 'program' parameter."}), 400

    program_path = os.path.join(USERSPACE_DIR, program)
    if not os.path.isfile(program_path) or not os.access(program_path, os.X_OK):
        return jsonify({"error": "Invalid program or not executable."}), 400

    global userspace_proc, userspace_thread, userspace_output
    if userspace_proc is not None and userspace_proc.poll() is None:
        return jsonify({"message": "Userspace program already running."}), 200

    with userspace_lock:
        userspace_output.clear()

    full_command = [program_path] + args.split()
    app.logger.info(f"Starting userspace program: sudo {' '.join(full_command)}")
    try:
        userspace_proc = subprocess.Popen(
            ["sudo"] + full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
    except Exception as ex:
        app.logger.error(f"Error starting userspace program: {ex}")
        return jsonify({"error": str(ex)}), 500

    def run_userspace_output():
        global userspace_proc
        while True:
            line = userspace_proc.stdout.readline()
            if line:
                line = line.strip()
                app.logger.info(f"Userspace output: {line}")
                with userspace_lock:
                    userspace_output.append(line)
            else:
                if userspace_proc.poll() is not None:
                    app.logger.info("Userspace program terminated.")
                    break
                time.sleep(0.1)
        userspace_proc.stdout.close()
        userspace_proc.wait()

    userspace_thread = threading.Thread(target=run_userspace_output, daemon=True)
    userspace_thread.start()
    return jsonify({"message": "Userspace program started."}), 200


@app.route("/api/stop_userspace", methods=["POST"])
def stop_userspace():
    global userspace_proc
    if userspace_proc is not None and userspace_proc.poll() is None:
        try:
            subprocess.run(["sudo", "kill", "-15", str(userspace_proc.pid)], check=True)
            userspace_proc.wait(timeout=5)
            app.logger.info("Userspace program terminated successfully.")
            return jsonify({"message": "Userspace program stopped."}), 200
        except Exception as ex:
            app.logger.error(f"Error stopping userspace program: {ex}")
            return jsonify({"error": str(ex)}), 500
    else:
        return jsonify({"message": "Userspace program is not running."}), 200


@app.route("/api/userspace_output", methods=["GET"])
def get_userspace_output():
    global userspace_output
    with userspace_lock:
        output_copy = userspace_output.copy()
    return jsonify({"output": output_copy})

@app.route("/api/userspace_status", methods=["GET"])
def userspace_status():
    global userspace_proc
    # If userspace_proc is not None and hasn't exited (poll() returns None), it's running
    running = (userspace_proc is not None and userspace_proc.poll() is None)
    return jsonify({"running": running}), 200

@app.route("/api/dump_userspace_output", methods=["GET"])
def dump_userspace_output():
    global userspace_output
    with userspace_lock:
        output_text = "\n".join(userspace_output)
    response = Response(output_text, mimetype='text/plain')
    response.headers["Content-Disposition"] = "attachment;filename=userspace_output.txt"
    return response


# ------------------------
# Additional Endpoint: Performance Metrics
# ------------------------
@app.route("/api/performance_metrics", methods=["GET"])
def performance_metrics():
    try:
        import psutil
    except ImportError:
        return jsonify({"error": "psutil module is not installed."}), 500

    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        memory_percent = mem.percent
        return jsonify({"cpu": cpu_percent, "memory": memory_percent})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
