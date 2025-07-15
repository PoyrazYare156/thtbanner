async function scanHeaders() {
  const url = document.getElementById('targetUrl').value;
  if (!url) {
    alert("Please enter a valid URL.");
    return;
  }

  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = "<p>Scanning...</p>";

  try {
    const response = await fetch("https://api.allorigins.win/raw?url=" + encodeURIComponent(url), {
      method: "HEAD"
    });

    const securityHeaders = [
      { key: "content-security-policy", name: "Content-Security-Policy", points: 20, fix: "Add a strong CSP like: default-src 'self';" },
      { key: "strict-transport-security", name: "Strict-Transport-Security", points: 15, fix: "Enable HSTS to enforce HTTPS connections." },
      { key: "x-frame-options", name: "X-Frame-Options", points: 10, fix: "Add X-Frame-Options: DENY or SAMEORIGIN." },
      { key: "x-content-type-options", name: "X-Content-Type-Options", points: 10, fix: "Add X-Content-Type-Options: nosniff." },
      { key: "referrer-policy", name: "Referrer-Policy", points: 10, fix: "Set a strict Referrer-Policy (e.g., no-referrer or same-origin)." },
      { key: "permissions-policy", name: "Permissions-Policy", points: 10, fix: "Define Permissions-Policy to restrict browser features." }
    ];

    const headers = [...response.headers.entries()];
    let report = [];
    let jsonReport = { url, date: new Date().toISOString(), score: 100, risk: "", headers: {}, recommendations: [] };
    let score = 100;
    let missing = [];

    for (const header of securityHeaders) {
      const match = headers.find(([key]) => key.toLowerCase() === header.key);
      if (match) {
        if (header.key === "content-security-policy") {
          let value = match[1];
          jsonReport.headers[header.name] = value;
          if (value.includes("*") || value.includes("unsafe-inline") || value.includes("unsafe-eval")) {
            report.push(`<p style="color:orange;"><strong>${header.name}:</strong> ⚠️ Weak Policy: ${value}</p>`);
            score -= 10;
            jsonReport.recommendations.push("CSP policy is weak: avoid unsafe-inline, unsafe-eval, *.");
          } else if (!value.includes("nonce") && !value.includes("strict-dynamic")) {
            report.push(`<p style="color:orange;"><strong>${header.name}:</strong> ⚠️ Missing nonce or strict-dynamic in CSP.</p>`);
            score -= 5;
            jsonReport.recommendations.push("Consider adding CSP nonce or 'strict-dynamic' for better protection.");
          } else {
            report.push(`<p><strong>${header.name}:</strong> ✅ ${value}</p>`);
          }
        } else {
          jsonReport.headers[header.name] = match[1];
          report.push(`<p><strong>${header.name}:</strong> ✅ ${match[1]}</p>`);
        }
      } else {
        report.push(`<p style="color:red;"><strong>${header.name}:</strong> ❌ Missing<br><em>Recommendation:</em> ${header.fix}</p>`);
        score -= header.points;
        missing.push(header.name);
        jsonReport.headers[header.name] = null;
        jsonReport.recommendations.push(`${header.name} is missing. ${header.fix}`);
      }
    }

    let risk = "🟩 Low Risk";
    if (score < 80) risk = "🟨 Medium Risk";
    if (score < 50) risk = "🟥 High Risk";
    jsonReport.score = score;
    jsonReport.risk = risk;

    const resultHTML = `
      <h3>Scan Result:</h3>
      <p><strong>Security Score:</strong> ${score}/100 (${risk})</p>
      ${report.join("")}
      <button onclick="exportPDF()">📄 Export as PDF</button>
      <button onclick='exportJSON(${JSON.stringify(JSON.stringify(jsonReport))})'>💾 Export as JSON</button>
    `;

    resultDiv.innerHTML = resultHTML;

    // Save to history
    const history = JSON.parse(localStorage.getItem("scanHistory") || "[]");
    history.unshift({ url, date: new Date().toLocaleString(), score });
    localStorage.setItem("scanHistory", JSON.stringify(history.slice(0, 5)));

    renderHistory();
  } catch (err) {
    resultDiv.innerHTML = "<p style='color:red;'>Error scanning the URL. Make sure CORS is allowed and the site is reachable.</p>";
  }
}

function exportPDF() {
  const result = document.getElementById("result");
  const opt = {
    margin:       0.5,
    filename:     'scan-result.pdf',
    image:        { type: 'jpeg', quality: 0.98 },
    html2canvas:  {},
    jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
  };
  html2pdf().set(opt).from(result).save();
}

function exportJSON(dataStr) {
  const blob = new Blob([JSON.parse(dataStr)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "scan-result.json";
  a.click();
  URL.revokeObjectURL(url);
}

function renderHistory() {
  const history = JSON.parse(localStorage.getItem("scanHistory") || "[]");
  const div = document.getElementById("history");
  if (!div) return;
  div.innerHTML = "<h3>Recent Scans:</h3>" + history.map(h => 
    `<p>🔗 <a href="#" onclick="document.getElementById('targetUrl').value='${h.url}'; scanHeaders(); return false;">${h.url}</a> 
     (${h.date}) - Score: ${h.score}</p>`
  ).join("");
}

window.onload = renderHistory;


async function scanMultiple() {
  const input = document.getElementById("bulkUrls").value.trim();
  if (!input) return;

  const urls = input.split('\n').map(u => u.trim()).filter(u => u);
  const resultDiv = document.getElementById("bulkResults");
  resultDiv.innerHTML = "<p>Scanning multiple domains...</p>";

  let results = [["URL", "Score", "Risk Level"]];

  for (const url of urls) {
    try {
      const response = await fetch("https://api.allorigins.win/raw?url=" + encodeURIComponent(url), {
        method: "HEAD"
      });

      const headers = [...response.headers.entries()];
      let score = 100;
      let risk = "Low";
      let cspHeader = headers.find(([k]) => k.toLowerCase() === "content-security-policy");
      if (!cspHeader) score -= 20;
      else {
        if (cspHeader[1].includes("*") || cspHeader[1].includes("unsafe-inline")) score -= 10;
        if (!cspHeader[1].includes("nonce") && !cspHeader[1].includes("strict-dynamic")) score -= 5;
      }

      const mustHave = ["strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
      for (const key of mustHave) {
        if (!headers.find(([k]) => k.toLowerCase() === key)) {
          score -= 10;
        }
      }

      if (score < 80) risk = "Medium";
      if (score < 50) risk = "High";

      results.push([url, score, risk]);
    } catch {
      results.push([url, "Error", "N/A"]);
    }
  }

  const table = results.map(row => "<tr>" + row.map(col => `<td>${col}</td>`).join("") + "</tr>").join("");
  resultDiv.innerHTML = "<table border='1' style='margin-top:10px; width:100%;'>" + table + "</table>";

  localStorage.setItem("bulkScanResults", JSON.stringify(results));
}

function exportCSV() {
  const rows = JSON.parse(localStorage.getItem("bulkScanResults") || "[]");
  if (!rows.length) return;

  const csv = rows.map(r => r.map(val => `"${val}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "bulk-scan-results.csv";
  a.click();
  URL.revokeObjectURL(url);
}
