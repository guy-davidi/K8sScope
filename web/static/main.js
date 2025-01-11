// main.js

document.addEventListener("DOMContentLoaded", () => {
  fetchPrograms();
});

// Show or hide the loading spinner
function showLoading(show) {
  const spinner = document.querySelector(".loading");
  spinner.style.display = show ? "block" : "none";
}

// Show a Bootstrap 5 toast message
function showToast(message, isError = false) {
  // Create toast element
  const toastContainer = document.getElementById("toastContainer");
  const toastEl = document.createElement("div");
  toastEl.className = "toast align-items-center text-bg-" + (isError ? "danger" : "success");
  toastEl.role = "alert";
  toastEl.ariaLive = "assertive";
  toastEl.ariaAtomic = "true";

  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;

  toastContainer.appendChild(toastEl);

  // Initialize and show
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  bsToast._element.addEventListener('hidden.bs.toast', () => {
    toastEl.remove();
  });
}

// Fetch .o files & loaded eBPF
async function fetchPrograms() {
  showLoading(true);
  try {
    const res = await fetch("/api/programs");
    const data = await res.json();
    if (data.error) {
      showToast(data.error, true);
      return;
    }
    updateOFileList(data.programs || []);
    updateLoadedTable(data.loaded || []);
  } catch (err) {
    showToast("Error fetching programs: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

// Populate .o file list
function updateOFileList(programs) {
  const listEl = document.getElementById("o-file-list");
  listEl.innerHTML = "";
  if (programs.length === 0) {
    const li = document.createElement("li");
    li.className = "list-group-item text-muted";
    li.textContent = "No .o files found in ebpf/src.";
    listEl.appendChild(li);
    return;
  }
  programs.forEach((prog) => {
    const li = document.createElement("li");
    li.className = "list-group-item d-flex justify-content-between align-items-center";
    li.textContent = prog;

    // Click to fill the form
    li.style.cursor = "pointer";
    li.addEventListener("click", () => {
      document.getElementById("programInput").value = prog;
    });
    listEl.appendChild(li);
  });
}

// Populate loaded table
function updateLoadedTable(loaded) {
  const tbody = document.getElementById("loaded-table-body");
  tbody.innerHTML = "";
  if (loaded.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.textContent = "No loaded programs found.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }
  loaded.forEach((prog) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${prog.id}</td>
      <td>${prog.name}</td>
      <td>${prog.type}</td>
      <td>${prog.pinned || "Not pinned"}</td>
    `;
    tbody.appendChild(row);
  });
}

// Handle the single form
document.getElementById("ebpf-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showLoading(true);

  const action = document.getElementById("action").value; // load, attach, detach, unload
  const program = document.getElementById("programInput").value.trim();
  const pinPath = document.getElementById("pinPath").value.trim();
  const typeVal = document.getElementById("typeInput").value.trim();
  const targetVal = document.getElementById("targetInput").value.trim();

  try {
    if (action === "load") {
      await doLoad(program, pinPath, typeVal);
    } else if (action === "unload") {
      await doUnload(program, pinPath);
    } else if (action === "attach") {
      await doAttach(pinPath, typeVal, targetVal);
    } else if (action === "detach") {
      await doDetach(pinPath, typeVal, targetVal);
    } else {
      showToast("Unknown action: " + action, true);
    }
    // Refresh lists
    fetchPrograms();
  } catch (err) {
    showToast("Error: " + err.message, true);
  } finally {
    showLoading(false);
  }
});

/* ------- Action Helpers ------- */

// 1) Load
async function doLoad(program, pinPath, progType) {
  if (!program) {
    showToast("Please select or type a .o file name", true);
    throw new Error("No program specified");
  }
  const body = { program };
  if (pinPath) body.pin_path = pinPath;
  if (progType) body.type = progType;

  const res = await fetch("/api/programs/load", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.error) {
    showToast(data.error, true);
  } else {
    showToast(data.message, false);
  }
}

// 2) Unload
async function doUnload(program, pinPath) {
  const body = {};
  if (pinPath) {
    body.pin_path = pinPath;
  } else if (program) {
    body.program = program;
  } else {
    showToast("Please provide a pinPath or program name to unload", true);
    throw new Error("No unload path or program");
  }
  const res = await fetch("/api/programs/unload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.error) {
    showToast(data.error, true);
  } else {
    showToast(data.message, false);
  }
}

// 3) Attach
async function doAttach(pinPath, attachType, target) {
  if (!pinPath) {
    showToast("Pin path required for attach", true);
    throw new Error("No pin path");
  }
  const body = { pin_path: pinPath };
  if (attachType) body.attach_type = attachType;
  if (target) body.target = target;

  const res = await fetch("/api/programs/attach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.error) {
    showToast(data.error, true);
  } else {
    showToast(data.message, false);
  }
}

// 4) Detach
async function doDetach(pinPath, attachType, target) {
  if (!pinPath) {
    showToast("Pin path required for detach", true);
    throw new Error("No pin path");
  }
  if (!attachType) {
    showToast("attach_type required for detach", true);
    throw new Error("No attach type");
  }
  const body = { pin_path: pinPath, attach_type: attachType };
  if (target) body.target = target;

  const res = await fetch("/api/programs/detach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.error) {
    showToast(data.error, true);
  } else {
    showToast(data.message, false);
  }
}
