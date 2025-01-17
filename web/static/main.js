// Global variables for Chart.js and polling intervals
let logChart = null;
let pollingInterval = null;
let userspacePollingInterval = null;
let userspaceChart = null;

/* -------------------------------
   Utility Functions
------------------------------- */
function showLoading(show) {
  const spinner = document.querySelector(".loading");
  if (!spinner) return;
  spinner.style.display = show ? "block" : "none";
}

function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, "&amp;")
               .replace(/</g, "&lt;")
               .replace(/>/g, "&gt;")
               .replace(/"/g, "&quot;")
               .replace(/'/g, "&#039;");
}

function showToast(message, isError = false) {
  console.log(`[DEBUG] Toast: ${message} (isError=${isError})`);
  const toastContainer = document.getElementById("toastContainer");
  if (!toastContainer) {
    console.error("[DEBUG] toastContainer element not found.");
    return;
  }
  const toastEl = document.createElement("div");
  toastEl.className = `toast align-items-center text-bg-${isError ? "danger" : "success"}`;
  toastEl.role = "alert";
  toastEl.ariaLive = "assertive";
  toastEl.ariaAtomic = "true";
  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${escapeHtml(message)}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;
  toastContainer.appendChild(toastEl);
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  bsToast._element.addEventListener("hidden.bs.toast", () => {
    toastEl.remove();
  });
}

/* -------------------------------
   API and DOM Update Functions
------------------------------- */
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
    li.tabIndex = 0;
    li.addEventListener("click", () => {
      listEl.querySelectorAll(".active").forEach((item) => item.classList.remove("active"));
      li.classList.add("active");
      document.getElementById("programInput").value = prog;
    });
    li.addEventListener("keydown", (event) => { if (event.key === "Enter") li.click(); });
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
              <span class="badge bg-${prog.gpl_compatible ? "success" : "danger"}">${prog.gpl_compatible ? "Yes" : "No"}</span>
            </li>
            <li class="list-group-item">
              <strong>Loaded At:</strong> ${new Date(prog.loaded_at * 1000).toLocaleString()}
            </li>
            <li class="list-group-item"><strong>UID:</strong> ${prog.uid}</li>
            <li class="list-group-item">
              <strong>Orphaned:</strong>
              <span class="badge bg-${prog.orphaned ? "warning" : "secondary"}">${prog.orphaned ? "Yes" : "No"}</span>
            </li>
            <li class="list-group-item">
              <strong>Bytes Translated:</strong> ${prog.bytes_xlated}
            </li>
            <li class="list-group-item">
              <strong>JITed:</strong> <span class="badge bg-${prog.jited ? "primary" : "secondary"}">${prog.jited ? "Yes" : "No"}</span>
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

/* -------------------------------
   Form Submission & eBPF Actions
------------------------------- */
function attachFormEvent() {
  const ebpfForm = document.getElementById("ebpf-form");
  if (ebpfForm) {
    ebpfForm.addEventListener("submit", handleFormSubmit);
  } else {
    console.error("[DEBUG] ebpf-form element not found.");
  }
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
  if (pinPath) body.pin_path = pinPath;
  else if (program) body.program = program;
  else {
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
      if (defaultPin.endsWith(".bpf.o")) defaultPin = defaultPin.slice(0, -6);
      else defaultPin = defaultPin.split(".")[0];
      pinPath = "/sys/fs/bpf/" + defaultPin;
    } else {
      showToast("Pin path required for attach", true);
      throw new Error("No pin path");
    }
  }
  if (!attachType) attachType = "xdp";
  if (!target) target = attachType.toLowerCase() === "xdp" ? "eth0" : "tracepoint/syscalls/sys_enter_execve";
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

/* -------------------------------
   Log and Visualization Functions (eBPF)
------------------------------- */
function fetchCollectorEvents() {
  fetch("/api/collector_events")
    .then((response) => response.json())
    .then((data) => {
      const eventsDiv = document.getElementById("collector-events");
      eventsDiv.innerHTML = "";
      data.events.slice().reverse().forEach((event) => {
        const eventElem = document.createElement("div");
        eventElem.className = "border-bottom py-1";
        eventElem.style.fontSize = "0.8rem";
        eventElem.textContent = event;
        eventsDiv.appendChild(eventElem);
      });
      if (logChart) updateChartData(data.events);
    })
    .catch((err) => console.error("Failed to fetch collector events:", err));
}

function initializeChart() {
  const ctx = document.getElementById("logChart").getContext("2d");
  logChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "eBPF Log Count Over Time",
          data: [],
          fill: false,
          borderColor: "rgb(75, 192, 192)",
          tension: 0.1,
        },
      ],
    },
    options: {
      responsive: true,
      scales: { x: { title: { display: true, text: "Time" } }, y: { title: { display: true, text: "Count" } } },
    },
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

/* -------------------------------
   Collection Start/Stop Functions (eBPF)
------------------------------- */
function startPolling() {
  if (!pollingInterval) {
    pollingInterval = setInterval(fetchCollectorEvents, 2000);
    console.log("[DEBUG] eBPF polling started.");
  }
}

function stopPolling() {
  clearInterval(pollingInterval);
  pollingInterval = null;
  console.log("[DEBUG] eBPF polling stopped.");
}

/* -------------------------------
   Userspace Program Management Functions
------------------------------- */
async function loadUserspacePrograms() {
  try {
    const res = await fetch("/api/userspace_programs");
    if (!res.ok) throw new Error("Failed to load userspace programs");
    const data = await res.json();
    console.log("Userspace programs received:", data.programs);
    const select = document.getElementById("userspaceProgramSelect");
    select.innerHTML = "";
    data.programs.forEach((prog) => {
      const option = document.createElement("option");
      option.value = prog;
      option.textContent = prog;
      select.appendChild(option);
    });
  } catch (err) {
    console.error(err);
    showToast("Error loading userspace programs: " + err.message, true);
  }
}

function startUserspaceProgram() {
  const programSelect = document.getElementById("userspaceProgramSelect");
  const argsInput = document.getElementById("userspaceArgs");
  const program = programSelect.value;
  const args = argsInput.value.trim();
  if (!program) {
    showToast("Please select a userspace program", true);
    return;
  }
  fetch("/api/start_userspace", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ program, args }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) showToast(data.error, true);
      else {
        showToast(data.message);
        document.getElementById("stopUserspaceBtn").disabled = false;
        document.getElementById("startUserspaceBtn").disabled = true;
      }
    })
    .catch((err) => {
      console.error(err);
      showToast("Error starting userspace program: " + err.message, true);
    });
}

function stopUserspaceProgram() {
  fetch("/api/stop_userspace", { method: "POST" })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) showToast(data.error, true);
      else {
        showToast(data.message);
        document.getElementById("stopUserspaceBtn").disabled = true;
        document.getElementById("startUserspaceBtn").disabled = false;
      }
    })
    .catch((err) => {
      console.error(err);
      showToast("Error stopping userspace program: " + err.message, true);
    });
}

function fetchUserspaceOutput() {
  fetch("/api/userspace_output")
    .then((response) => response.json())
    .then((data) => {
      const outputDiv = document.getElementById("userspaceOutput");
      outputDiv.textContent = data.output.join("\n");
      updateUserspaceChartData(data.output.length);
    })
    .catch((err) => console.error("Failed to fetch userspace output:", err));
}

function startUserspacePolling() {
  if (!userspacePollingInterval) {
    userspacePollingInterval = setInterval(fetchUserspaceOutput, 2000);
    console.log("[DEBUG] Userspace polling started.");
  }
}

function stopUserspacePolling() {
  clearInterval(userspacePollingInterval);
  userspacePollingInterval = null;
  console.log("[DEBUG] Userspace polling stopped.");
}

function initializeUserspaceChart() {
  const ctx = document.getElementById("userspaceChart").getContext("2d");
  userspaceChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Userspace Lines Over Time",
          data: [],
          fill: false,
          borderColor: "rgb(255, 99, 132)",
          tension: 0.1,
        },
      ],
    },
    options: {
      responsive: true,
      scales: { x: { title: { display: true, text: "Time" } }, y: { title: { display: true, text: "Lines" } } },
    },
  });
}

function updateUserspaceChartData(linesCount) {
  const now = new Date().toLocaleTimeString();
  if (userspaceChart.data.labels.length >= 10) {
    userspaceChart.data.labels.shift();
    userspaceChart.data.datasets[0].data.shift();
  }
  userspaceChart.data.labels.push(now);
  userspaceChart.data.datasets[0].data.push(linesCount);
  userspaceChart.update();
}

function initializeUserspaceDumpHandler() {
  const dumpBtn = document.getElementById("dumpUserspaceOutputBtn");
  dumpBtn.addEventListener("click", () => {
    window.location.href = "/api/dump_userspace_output";
  });
}

/* -------------------------------
   Button Handlers for eBPF Collection
------------------------------- */
function initializeCollectionButtonHandlers() {
  const startBtn = document.getElementById("startCollectionBtn");
  const stopBtn = document.getElementById("stopCollectionBtn");
  const toggleLogsBtn = document.getElementById("toggleLogsBtn");
  const collectorPanel = document.getElementById("collector-panel");

  startBtn.addEventListener("click", () => {
    startPolling();
    startBtn.disabled = true;
    stopBtn.disabled = false;
    showToast("eBPF Collection started");
  });

  stopBtn.addEventListener("click", async function () {
    try {
      const res = await fetch("/api/stop_collection", { method: "POST" });
      const data = await res.json();
      showToast(data.message || data.error, data.error ? true : false);
      stopPolling();
      stopBtn.disabled = true;
      startBtn.disabled = false;
    } catch (err) {
      console.error("Failed to stop eBPF collector:", err);
      showToast("Error stopping eBPF collector: " + err.message, true);
    }
  });

  toggleLogsBtn.addEventListener("click", () => {
    if (collectorPanel.style.display === "none" || collectorPanel.style.display === "") {
      collectorPanel.style.display = "block";
      toggleLogsBtn.textContent = "Hide Logs";
      startPolling();
    } else {
      collectorPanel.style.display = "none";
      toggleLogsBtn.textContent = "Show Logs";
      stopPolling();
    }
  });
}

/* -------------------------------
   Button Handlers for Userspace Management
------------------------------- */
function initializeUserspaceManagementHandlers() {
  const startBtn = document.getElementById("startUserspaceBtn");
  const stopBtn = document.getElementById("stopUserspaceBtn");
  const toggleOutputBtn = document.getElementById("toggleUserspaceOutputBtn");
  const toggleVizBtn = document.getElementById("toggleUserspaceVizBtn");
  const outputPanel = document.getElementById("userspaceOutputPanel");
  const vizPanel = document.getElementById("userspaceVizPanel");

  startBtn.addEventListener("click", startUserspaceProgram);
  stopBtn.addEventListener("click", stopUserspaceProgram);

  toggleOutputBtn.addEventListener("click", () => {
    if (outputPanel.style.display === "none" || outputPanel.style.display === "") {
      outputPanel.style.display = "block";
      toggleOutputBtn.textContent = "Hide Output";
      startUserspacePolling();
    } else {
      outputPanel.style.display = "none";
      toggleOutputBtn.textContent = "Show Output";
      stopUserspacePolling();
    }
  });

  toggleVizBtn.addEventListener("click", () => {
    if (vizPanel.style.display === "none" || vizPanel.style.display === "") {
      vizPanel.style.display = "block";
      toggleVizBtn.textContent = "Hide Visualization";
      if (!userspaceChart) initializeUserspaceChart();
    } else {
      vizPanel.style.display = "none";
      toggleVizBtn.textContent = "Visualize";
    }
  });

  initializeUserspaceDumpHandler();
}

/* -------------------------------
   Other Button Handlers (eBPF)
------------------------------- */
function initializeButtonHandlers() {
  document.getElementById("dumpLogsBtn").addEventListener("click", () => {
    window.location.href = "/api/dump_logs";
  });
  document.getElementById("toggleVizBtn").addEventListener("click", function () {
    const vizPanel = document.getElementById("visualization-panel");
    if (vizPanel.style.display === "none" || vizPanel.style.display === "") {
      vizPanel.style.display = "block";
      this.textContent = "Hide Visualization";
      if (!logChart) initializeChart();
    } else {
      vizPanel.style.display = "none";
      this.textContent = "Visualize";
    }
  });
}

/* -------------------------------
   DOM Initialization
------------------------------- */
document.addEventListener("DOMContentLoaded", () => {
  console.log("[DEBUG] DOM Content Loaded. Fetching programs...");
  fetchPrograms();
  attachFormEvent();
  initializeButtonHandlers();             // For eBPF Dump & Visualization
  initializeCollectionButtonHandlers();   // For eBPF Collection & Logs Toggle
  initializeUserspaceManagementHandlers();  // For Userspace Management
  loadUserspacePrograms();                // Populate the userspace selector
});
