#!/usr/bin/env python3
import os
import json
import subprocess
import threading
import time
from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__, template_folder='templates')

# Directory for scanning .o files (adjust as needed)
EBPF_SRC_DIR = os.path.abspath("ebpf/src")

# Global list and lock for storing collector events
collected_events = []
events_lock = threading.Lock()

# Global flags and variables for controlling the collector
collector_started = False
collector_thread = None
collector_proc = None  # Global variable to hold the collector process


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


# REST endpoints for managing eBPF programs

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

    # Start the collector if it hasn't been started yet
    global collector_started
    if not collector_started:
        start_collector()
        collector_started = True
        app.logger.info("Collector started after successful load.")

    # Clear any previously collected events to show only new ones.
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
# Collector Endpoints
# ------------------------

@app.route("/api/collector_events", methods=["GET"])
def get_collector_events():
    """Return real-time events collected by the C collector."""
    with events_lock:
        events_copy = collected_events.copy()
    return jsonify({"events": events_copy})


@app.route("/api/clear_logs", methods=["POST"])
def clear_logs():
    """Clear the collected collector events."""
    with events_lock:
        collected_events.clear()
    return jsonify({"message": "Collector logs cleared"}), 200


@app.route("/api/dump_logs", methods=["GET"])
def dump_logs():
    """
    Dump all currently collected logs as a downloadable text file.
    The log entries are joined by newlines.
    """
    with events_lock:
        log_text = "\n".join(collected_events)
    # Create a response with the logs and set content-disposition for a download
    response = Response(log_text, mimetype='text/plain')
    response.headers["Content-Disposition"] = "attachment;filename=collector_logs.txt"
    return response


@app.route("/api/start_collection", methods=["POST"])
def start_collection_endpoint():
    """Start the collector process if it is not already running."""
    global collector_started
    if collector_started:
        return jsonify({"message": "Collector process already running."}), 200
    try:
        start_collector()
        collector_started = True
        app.logger.info("Collector process started via /api/start_collection endpoint.")
        return jsonify({"message": "Collector process started."}), 200
    except Exception as ex:
        app.logger.error(f"Failed to start collector process: {ex}")
        return jsonify({"error": f"Failed to start collector process: {ex}"}), 500


@app.route("/api/stop_collection", methods=["POST"])
def stop_collection():
    """Stop the collector process if it's running."""
    global collector_proc, collector_started
    if collector_proc is not None and collector_proc.poll() is None:
        try:
            collector_proc.terminate()  # Request termination
            collector_proc.wait(timeout=5)  # Wait up to 5 seconds
            collector_started = False
            app.logger.info("Collector process terminated successfully.")
            return jsonify({"message": "Collector process stopped."}), 200
        except Exception as ex:
            app.logger.error(f"Failed to stop collector process: {ex}")
            return jsonify({"error": f"Failed to stop collector process: {ex}"}), 500
    else:
        collector_started = False
        return jsonify({"message": "Collector process is not running."}), 200


# ------------------------
# Collector Integration
# ------------------------

def start_collector():
    """
    Launch the C collector executable ('./exec') as a subprocess in a background thread.
    Each output line is stored and logged.
    """
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
            collector_proc = proc  # Store the process globally
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
                # Check if the process has terminated
                if proc.poll() is not None:
                    app.logger.info("Collector process terminated.")
                    break
                time.sleep(0.1)

        proc.stdout.close()
        proc.wait()
        collector_proc = None  # Clear the global process reference

    global collector_thread
    collector_thread = threading.Thread(target=run_collector, daemon=True)
    collector_thread.start()


if __name__ == "__main__":
    # For production, consider using Gunicorn or another production server.
    app.run(host="127.0.0.1", port=5000, debug=True)
