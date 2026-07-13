const text = (tag, value) => {
  const node = document.createElement(tag);
  node.textContent = value;
  return node;
};

async function loadJobs() {
  const status = document.getElementById("status");
  try {
    const response = await fetch("/api/v1/jobs?limit=50", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const jobs = await response.json();
    const body = document.getElementById("jobs");
    body.replaceChildren();
    for (const job of jobs) {
      const row = document.createElement("tr");
      const idCell = document.createElement("td");
      idCell.append(text("code", job.id));
      row.append(idCell);
      row.append(text("td", job.request.source.location));
      const state = text("td", job.state);
      state.className = job.state;
      row.append(state);
      row.append(text("td", job.updated_at));
      const reportCell = document.createElement("td");
      if (job.state === "completed") {
        const link = document.createElement("a");
        link.href = `/api/v1/jobs/${encodeURIComponent(job.id)}/report.html`;
        link.textContent = "Open";
        reportCell.append(link);
      }
      row.append(reportCell);
      body.append(row);
    }
    status.textContent = `${jobs.length} job(s)`;
  } catch (error) {
    status.textContent = `Unable to load jobs: ${error.message}`;
  }
}

document.getElementById("refresh").addEventListener("click", loadJobs);
loadJobs();
