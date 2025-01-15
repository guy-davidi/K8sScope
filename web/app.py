#!/usr/bin/env python3
import os
import json
import subprocess
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')

# Directory for scanning .o files (adjust as needed)
EBPF_SRC_DIR = os.path.abspath("ebpf/src")


def make_absolute_pin_path(pin_path):
    """
    If pin_path is not absolute (does not start with '/'), assume it's relative to /sys/fs/bpf
    """
    return os.path.join("/sys/fs/bpf", pin_path) if not pin_path.startswith("/") else pin_path


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
    pin_path = make_absolute_pin_path(data.get("pin_path"))
    attach_type = data.get("attach_type", "tracepoint")
    target = data.get("target") or ("tracepoint/syscalls/sys_enter_execve" if attach_type == "tracepoint" else "eth0")

    if attach_type == "tracepoint":
        cmd = ["bpftool", "prog", "attach", "pinned", pin_path, "tracepoint", target]
    elif attach_type == "xdp":
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
    pin_path = make_absolute_pin_path(data.get("pin_path"))
    attach_type = data.get("attach_type")
    target = data.get("target")

    if not attach_type or not pin_path or not target:
        return jsonify({"error": "Missing required parameters"}), 400

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


if __name__ == "__main__":
    # For production, consider using a proper production server like gunicorn
    app.run(host="127.0.0.1", port=5000, debug=True)