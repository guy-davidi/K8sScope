from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

PROGRAMS_DIR = "/path/to/ebpf_programs"

@app.route('/programs', methods=['GET'])
def list_programs():
    """List available eBPF programs."""
    programs = [name for name in os.listdir(PROGRAMS_DIR) if os.path.isdir(os.path.join(PROGRAMS_DIR, name))]
    return jsonify(programs)

@app.route('/programs/load', methods=['POST'])
def load_program():
    """Load a specified eBPF program."""
    program = request.json.get('program')
    program_path = os.path.join(PROGRAMS_DIR, program)
    
    if not os.path.isdir(program_path):
        return jsonify({"error": "Program not found"}), 404
    
    try:
        # Run make to build the program
        subprocess.run(["make", "-C", program_path], check=True)
        
        # Attach the eBPF program (example using bpftool)
        prog_obj = os.path.join(program_path, f"{program}.o")
        subprocess.run(["bpftool", "prog", "load", prog_obj, "/sys/fs/bpf/my_prog"], check=True)
        
        return jsonify({"message": f"Program {program} loaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to load program {program}: {str(e)}"}), 500

@app.route('/programs/unload', methods=['POST'])
def unload_program():
    """Unload a specified eBPF program."""
    program = request.json.get('program')
    
    try:
        # Detach and unload the program (example using bpftool)
        subprocess.run(["bpftool", "prog", "unload", "/sys/fs/bpf/my_prog"], check=True)
        return jsonify({"message": f"Program {program} unloaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to unload program {program}: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)