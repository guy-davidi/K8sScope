// Run once the DOM is fully loaded
document.addEventListener("DOMContentLoaded", () => {
  console.log("[DEBUG] DOM Content Loaded. Fetching programs...");
  fetchPrograms();

  const ebpfForm = document.getElementById("ebpf-form");
  if (ebpfForm) {
    ebpfForm.addEventListener("submit", handleFormSubmit);
  } else {
    console.error("[DEBUG] ebpf-form element not found.");
  }
});

// Function to show/hide loading indicator (if applicable)
function showLoading(show) {
  const spinner = document.querySelector(".loading");
  if (!spinner) return;
  spinner.style.display = show ? "block" : "none";
}

/**
 * Opens a new window with a styled error message.
 * Utilizes Bootstrap 5 for styling.
 * @param {string} message - The error message to display.
 */
function openErrorWindow(message) {
  const errorWindow = window.open("", "_blank", "width=600,height=400,scrollbars=yes");
  if (!errorWindow) {
    console.error("[DEBUG] Could not open error window.");
    return;
  }
  errorWindow.document.write(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Error Details</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        body { font-family: Arial, sans-serif; padding: 20px; background-color: #f8f9fa; }
        .error-container { max-width: 600px; margin: auto; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .error-header { background-color: #dc3545; color: white; padding: 15px; border-radius: 5px 5px 0 0; }
        .error-body { padding: 20px; background-color: white; border: 1px solid #dc3545; border-top: none; border-radius: 0 0 5px 5px; }
        .error-footer { margin-top: 20px; text-align: right; }
      </style>
    </head>
    <body>
      <div class="error-container">
        <div class="error-header">
          <h4 class="mb-0">An Error Occurred</h4>
        </div>
        <div class="error-body">
          <p>${escapeHtml(message)}</p>
        </div>
        <div class="error-footer">
          <button id="close-btn" class="btn btn-danger">Close</button>
        </div>
      </div>
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      <script>
        document.getElementById('close-btn').addEventListener('click', () => { window.close(); });
      </script>
    </body>
    </html>
  `);
  errorWindow.document.close();
}

/**
 * Escapes HTML characters to prevent XSS attacks.
 * @param {string} unsafe - The unsafe string to escape.
 * @returns {string} - The escaped string.
 */
function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, "&amp;")
               .replace(/</g, "&lt;")
               .replace(/>/g, "&gt;")
               .replace(/"/g, "&quot;")
               .replace(/'/g, "&#039;");
}

/**
 * Displays a Bootstrap 5 toast message.
 * @param {string} message - The message to display.
 * @param {boolean} isError - If true, shows an error.
 */
function showToast(message, isError = false) {
  console.log(`[DEBUG] Toast: ${message} (isError=${isError})`);
  if (isError) {
    openErrorWindow(message);
  }
  const toastContainer = document.getElementById("toastContainer");
  if (!toastContainer) {
    console.error("[DEBUG] toastContainer element not found.");
    return;
  }
  const toastEl = document.createElement("div");
  toastEl.className = "toast align-items-center text-bg-" + (isError ? "danger" : "success");
  toastEl.role = "alert";
  toastEl.ariaLive = "assertive";
  toastEl.ariaAtomic = "true";
  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${message}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;
  toastContainer.appendChild(toastEl);
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  bsToast._element.addEventListener("hidden.bs.toast", () => { toastEl.remove(); });
}

// --- Program and Form Functions ---

async function fetchPrograms() {
  console.log("[DEBUG] fetchPrograms() called");
  showLoading(true);
  try {
    const res = await fetch("/api/programs");
    if (!res.ok) {
      const errorMsg = await res.text();
      showToast(`Failed to fetch programs: ${errorMsg}`, true);
      return;
    }
    const data = await res.json();
    updateOFileList(data.programs || []);
    updateLoadedTable(data.loaded || []);
  } catch (err) {
    console.error("[DEBUG] fetchPrograms error:", err);
    showToast("Error fetching programs: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

function updateOFileList(programs) {
  const listEl = document.getElementById("o-file-list");
  if (!listEl) return;
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
    li.addEventListener("click", () => {
      document.getElementById("programInput").value = prog;
    });
    listEl.appendChild(li);
  });
}

function updateLoadedTable(loaded) {
  const tbody = document.getElementById("loaded-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (loaded.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No loaded programs found.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }
  loaded.forEach((prog, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${prog.id}</td>
      <td>${prog.name}</td>
      <td>${prog.type}</td>
      <td>${prog.pinned || "Not pinned"}</td>
      <td>
        <button class="btn btn-sm btn-info" data-bs-toggle="collapse" data-bs-target="#details-${index}">
          Details
        </button>
      </td>
    `;
    const detailsRow = document.createElement("tr");
    detailsRow.innerHTML = `
      <td colspan="5">
        <div id="details-${index}" class="collapse">
          <ul class="list-group list-group-flush">
            <li class="list-group-item"><strong>Tag:</strong> ${prog.tag}</li>
            <li class="list-group-item">
              <strong>GPL Compatible:</strong>
              <span class="badge bg-${prog.gpl_compatible ? "success" : "danger"}">
                ${prog.gpl_compatible ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Loaded At:</strong> ${new Date(prog.loaded_at * 1000).toLocaleString()}
            </li>
            <li class="list-group-item"><strong>UID:</strong> ${prog.uid}</li>
            <li class="list-group-item">
              <strong>Orphaned:</strong>
              <span class="badge bg-${prog.orphaned ? "warning" : "secondary"}">
                ${prog.orphaned ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Bytes Translated:</strong> ${prog.bytes_xlated}
            </li>
            <li class="list-group-item">
              <strong>JITed:</strong>
              <span class="badge bg-${prog.jited ? "primary" : "secondary"}">
                ${prog.jited ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Bytes JITed:</strong> ${prog.bytes_jited}
            </li>
            <li class="list-group-item">
              <strong>Bytes Memlock:</strong> ${prog.bytes_memlock}
            </li>
            <li class="list-group-item">
              <strong>Map IDs:</strong> ${prog.map_ids.join(", ") || "None"}
            </li>
            <li class="list-group-item">
              <strong>BTF ID:</strong> ${prog.btf_id}
            </li>
          </ul>
        </div>
      </td>
    `;
    tbody.appendChild(row);
    tbody.appendChild(detailsRow);
  });
}

async function handleFormSubmit(e) {
  e.preventDefault();
  showLoading(true);
  const action = document.getElementById("action").value;
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
      throw new Error("Unknown action");
    }
    await fetchPrograms();
  } catch (err) {
    showToast("Error: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

// Action Helpers
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
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Load failed");
  }
  showToast(data.message || "Program loaded");
}

async function doUnload(program, pinPath) {
  const body = {};
  if (pinPath) {
    body.pin_path = pinPath;
  } else if (program) {
    body.program = program;
  } else {
    showToast("Provide a pinPath or program name to unload", true);
    throw new Error("No unload path or program");
  }
  
  const res = await fetch("/api/programs/unload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  
  const data = await res.json();
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Unload failed");
  }
  showToast(data.message || "Program unloaded");
}

async function doAttach(pinPath, attachType, target) {
  if (!pinPath) {
    const program = document.getElementById("programInput").value.trim();
    if (program) {
      let defaultPin = program;
      if (defaultPin.endsWith(".bpf.o")) {
        defaultPin = defaultPin.slice(0, -6);
      } else {
        defaultPin = defaultPin.split('.')[0];
      }
      pinPath = "/sys/fs/bpf/" + defaultPin;
    } else {
      showToast("Pin path required for attach", true);
      throw new Error("No pin path");
    }
  }
  
  if (!attachType) {
    attachType = "xdp";
  }
  
  if (!target) {
    if (attachType.toLowerCase() === "xdp") {
      target = "eth0";
    } else if (attachType.toLowerCase() === "tracepoint") {
      target = "tracepoint/syscalls/sys_enter_execve";
    }
  }
  
  const body = { pin_path: pinPath, attach_type: attachType, target: target };
  
  const res = await fetch("/api/programs/attach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  
  const data = await res.json();
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Attach failed");
  }
  showToast(data.message || "Program attached");
}

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
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Detach failed");
  }
  showToast(data.message || "Program detached");
}

// --- Log and Visualization Functions ---

// Fetch collector events and update logs panel
function fetchCollectorEvents() {
  fetch('/api/collector_events')
    .then(response => response.json())
    .then(data => {
      const eventsDiv = document.getElementById('collector-events');
      eventsDiv.innerHTML = '';
      data.events.slice().reverse().forEach(event => {
        const eventElem = document.createElement('div');
        eventElem.className = 'border-bottom py-1';
        eventElem.style.fontSize = '0.8rem';
        eventElem.textContent = event;
        eventsDiv.appendChild(eventElem);
      });
      if (logChart) {
        updateChartData(data.events);
      }
    })
    .catch(err => console.error("Failed to fetch collector events:", err));
}

let pollingInterval;
function startPolling() {
  pollingInterval = setInterval(fetchCollectorEvents, 2000);
}
function stopPolling() {
  clearInterval(pollingInterval);
}

// Toggle log panel visibility
document.getElementById('toggleLogsBtn').addEventListener('click', function() {
  const panel = document.getElementById('collector-panel');
  const clearBtn = document.getElementById('clearLogsBtn');
  if (panel.style.display === 'none' || panel.style.display === '') {
    panel.style.display = 'block';
    clearBtn.style.display = 'inline-block';
    this.textContent = 'Hide Logs';
    startPolling();
  } else {
    panel.style.display = 'none';
    clearBtn.style.display = 'none';
    this.textContent = 'Show Logs';
    stopPolling();
  }
});

// Clear logs button handler
document.getElementById('clearLogsBtn').addEventListener('click', function() {
  fetch('/api/clear_logs', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
      showToast(data.message);
      document.getElementById('collector-events').innerHTML = '';
    })
    .catch(err => console.error("Failed to clear logs:", err));
});

// Stop Collection button handler
document.getElementById('stopCollectionBtn').addEventListener('click', async function() {
  try {
    const res = await fetch('/api/stop_collection', { method: 'POST' });
    const data = await res.json();
    showToast(data.message || data.error, data.error ? true : false);
    stopPolling();
    // Optionally, disable the stop button after stopping collection.
    this.disabled = true;
  } catch (err) {
    console.error("Failed to stop collector:", err);
    showToast("Error stopping collector: " + err.message, true);
  }
});

// --- Visualization using Chart.js ---
let logChart = null;
function initializeChart() {
  const ctx = document.getElementById('logChart').getContext('2d');
  logChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Log Count Over Time',
        data: [],
        fill: false,
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1
      }]
    },
    options: {
      responsive: true,
      scales: {
        x: { title: { display: true, text: 'Time' } },
        y: { title: { display: true, text: 'Count' } }
      }
    }
  });
}
function updateChartData(events) {
  const now = new Date().toLocaleTimeString();
  if (logChart.data.labels.length >= 10) {
    logChart.data.labels.shift();
    logChart.data.datasets[0].data.shift();
  }
  logChart.data.labels.push(now);
  logChart.data.datasets[0].data.push(events.length);
  logChart.update();
}
// Toggle visualization panel
document.getElementById('toggleVizBtn').addEventListener('click', function() {
  const vizPanel = document.getElementById('visualization-panel');
  if (vizPanel.style.display === 'none' || vizPanel.style.display === '') {
    vizPanel.style.display = 'block';
    this.textContent = 'Hide Visualization';
    if (!logChart) {
      initializeChart();
    }
  } else {
    vizPanel.style.display = 'none';
    this.textContent = 'Visualize Data';
  }
});

// --- Fetch Programs on Page Load ---
async function fetchPrograms() {
  console.log("[DEBUG] fetchPrograms() called");
  showLoading(true);
  try {
    const res = await fetch("/api/programs");
    if (!res.ok) {
      const errorMsg = await res.text();
      showToast(`Failed to fetch programs: ${errorMsg}`, true);
      return;
    }
    const data = await res.json();
    updateOFileList(data.programs || []);
    updateLoadedTable(data.loaded || []);
  } catch (err) {
    console.error("[DEBUG] fetchPrograms error:", err);
    showToast("Error fetching programs: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

// Initialization: update .o files and loaded programs on DOM load
document.addEventListener("DOMContentLoaded", () => {
  console.log("[DEBUG] DOM Content Loaded. Fetching programs...");
  fetchPrograms();
});
