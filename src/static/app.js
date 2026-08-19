const form = document.getElementById("traceroute-form");
const targetInput = document.getElementById("target");
const resultsBody = document.getElementById("results-body");
const resultsTable = document.getElementById("results-table");
const statusEl = document.getElementById("status");
const destinationEl = document.getElementById("destination");
const submitBtn = document.getElementById("submit-btn");

const COLUMNS = ["count", "host", "dns_name", "ASN", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"];

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) {
    return;
  }

  setLoading(true);
  clearResults();

  try {
    const response = await fetch(`/traceroute?target=${encodeURIComponent(target)}`);
    const data = await response.json();

    if (!response.ok) {
      showError(data.error || "Traceroute failed.");
      return;
    }

    renderResults(data);
  } catch (err) {
    showError("Network error while running traceroute.");
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  submitBtn.disabled = isLoading;
  statusEl.textContent = isLoading ? "Running traceroute\u2026" : "";
  statusEl.className = "status";
}

function clearResults() {
  resultsBody.innerHTML = "";
  resultsTable.classList.add("hidden");
  destinationEl.textContent = "";
  destinationEl.classList.add("hidden");
}

function showError(message) {
  statusEl.textContent = message;
  statusEl.className = "status error";
}

function renderResults(data) {
  const hubs = (data && data.report && data.report.hubs) || [];

  if (data && data.destination) {
    destinationEl.textContent = `Destination: ${data.destination}`;
    destinationEl.classList.remove("hidden");
  }

  if (hubs.length === 0) {
    showError("No results returned.");
    return;
  }

  hubs.forEach((hub) => {
    const row = document.createElement("tr");

    COLUMNS.forEach((column) => {
      const cell = document.createElement("td");

      if (column === "ASN") {
        const asnNumber = extractAsnNumber(hub[column]);
        if (asnNumber) {
          const link = document.createElement("a");
          link.href = `https://bgp.tools/as/${asnNumber}`;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = formatValue(column, hub[column]);
          cell.appendChild(link);
        } else {
          cell.textContent = formatValue(column, hub[column]);
        }
      } else {
        cell.textContent = formatValue(column, hub[column]);
      }

      row.appendChild(cell);
    });

    resultsBody.appendChild(row);
  });

  resultsTable.classList.remove("hidden");
  statusEl.textContent = "";
}

function formatValue(column, value) {
  if (column === "host") {
    return value || "???";
  }
  if (typeof value !== "number") {
    return value ?? "";
  }
  if (column === "Loss%") {
    return `${value.toFixed(1)}%`;
  }
  return value.toFixed(1);
}

function extractAsnNumber(value) {
  if (typeof value !== "string") {
    return null;
  }
  const match = value.match(/^AS(\d+)$/);
  return match ? match[1] : null;
}
