
from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)
EBPF_DIR = os.path.abspath("../ebpf")

@app.route('/')
def home():
    return "eBPF Program Manager Running!"

@app.route('/programs', methods=['GET'])
def list_programs():
    try:
        programs = [f for f in os.listdir(EBPF_DIR) if f.endswith('.o')]
        return jsonify(programs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/programs/load', methods=['POST'])
def load_program():
    program = request.json.get('program')
    program_path = os.path.join(EBPF_DIR, program)

    if not os.path.isfile(program_path):
        return jsonify({"error": "Program not found"}), 404

    try:
        subprocess.run(["bpftool", "prog", "load", program_path, "/sys/fs/bpf/" + program], check=True)
        return jsonify({"message": f"Program {program} loaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to load program {program}: {str(e)}"}), 500

@app.route('/programs/unload', methods=['POST'])
def unload_program():
    program = request.json.get('program')
    try:
        subprocess.run(["bpftool", "prog", "unload", "/sys/fs/bpf/" + program], check=True)
        return jsonify({"message": f"Program {program} unloaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to unload program {program}: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
