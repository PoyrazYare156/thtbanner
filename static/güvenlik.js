async function scanHeaders() {
  const url = document.getElementById('targetUrl').value.trim();
  if (!url) {
    alert("Lütfen geçerli bir URL girin.");
    return;
  }

  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = "<p>Tarama yapılıyor...</p>";

  try {
    const response = await fetch("/api/scan?url=" + encodeURIComponent(url));
    const data = await response.json();

    if (data.error) {
      resultDiv.innerHTML = `<p style="color:red;">❌ Hata: ${data.error}</p>`;
      return;
    }

    const headersToCheck = [
      { key: "content-security-policy", name: "Content-Security-Policy", points: 20, fix: "Güçlü bir CSP tanımlayın: default-src 'self';" },
      { key: "strict-transport-security", name: "Strict-Transport-Security", points: 15, fix: "HSTS etkinleştirilmeli." },
      { key: "x-frame-options", name: "X-Frame-Options", points: 10, fix: "DENY veya SAMEORIGIN olarak ayarlanmalı." },
      { key: "x-content-type-options", name: "X-Content-Type-Options", points: 10, fix: "nosniff olarak ayarlanmalı." },
      { key: "referrer-policy", name: "Referrer-Policy", points: 10, fix: "Örn: no-referrer ya da same-origin kullanılmalı." },
      { key: "permissions-policy", name: "Permissions-Policy", points: 10, fix: "Tarayıcı izinlerini sınırlandırın." }
    ];

    let score = 100;
    let report = [];
    let missing = [];

    for (const header of headersToCheck) {
      const val = data[header.key];
      if (val && val.value !== null) {
        if (header.key === "content-security-policy") {
          const value = val.value;
          if (value.includes("*") || value.includes("unsafe-inline") || value.includes("unsafe-eval")) {
            report.push(`<p style="color:orange;"><strong>${header.name}:</strong> ⚠️ Zayıf CSP: ${value}</p>`);
            score -= 10;
          } else {
            report.push(`<p><strong>${header.name}:</strong> ✅ ${value}</p>`);
          }
        } else {
          report.push(`<p><strong>${header.name}:</strong> ✅ ${val.value}</p>`);
        }
      } else {
        report.push(`<p style="color:red;"><strong>${header.name}:</strong> ❌ Eksik<br><em>📌 Öneri:</em> ${header.fix}</p>`);
        score -= header.points;
        missing.push(header.name);
      }
    }

    const risk = score >= 80 ? "🟩 Düşük Risk"
                : score >= 50 ? "🟨 Orta Risk"
                : "🟥 Yüksek Risk";

    resultDiv.innerHTML = `
      <h3>Tarama Sonucu:</h3>
      <p><strong>Güvenlik Skoru:</strong> ${score}/100 (${risk})</p>
      ${report.join("")}
      <button onclick="exportPDF()">📄 PDF Olarak Kaydet</button>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<p style="color:red;">Bağlantı hatası. Sunucuya ulaşılamıyor.</p>`;
  }
}

function exportPDF() {
  const result = document.getElementById("result");
  const opt = {
    margin: 0.5,
    filename: 'scan-result.pdf',
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: {},
    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
  };
  html2pdf().set(opt).from(result).save();
}

async function scanMultiple() {
  const input = document.getElementById("bulkUrls").value.trim();
  if (!input) return;

  const urls = input.split('\n').map(u => u.trim()).filter(u => u);
  const resultDiv = document.getElementById("bulkResults");
  resultDiv.innerHTML = "<p>Toplu tarama başlatıldı...</p>";

  let results = [["URL", "Skor", "Risk"]];

  for (const url of urls) {
    try {
      const response = await fetch("/api/scan?url=" + encodeURIComponent(url));
      const data = await response.json();

      let score = 100;
      if (!data["content-security-policy"] || !data["content-security-policy"].value) score -= 20;
      else {
        const val = data["content-security-policy"].value;
        if (val.includes("*") || val.includes("unsafe-inline")) score -= 10;
        if (!val.includes("nonce") && !val.includes("strict-dynamic")) score -= 5;
      }

      const mustHave = ["strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
      for (const key of mustHave) {
        if (!data[key] || data[key].value === null) score -= 10;
      }

      const risk = score >= 80 ? "Düşük"
                  : score >= 50 ? "Orta"
                  : "Yüksek";

      results.push([url, score, risk]);
    } catch {
      results.push([url, "Hata", "Bilinmiyor"]);
    }
  }

  const table = results.map(r => "<tr>" + r.map(c => `<td>${c}</td>`).join("") + "</tr>").join("");
  resultDiv.innerHTML = "<table><tr><th>URL</th><th>Skor</th><th>Risk</th></tr>" + table + "</table>";

  localStorage.setItem("bulkScanResults", JSON.stringify(results));
}

function exportCSV() {
  const rows = JSON.parse(localStorage.getItem("bulkScanResults") || "[]");
  if (!rows.length) return;

  const csv = rows.map(r => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "bulk-scan-results.csv";
  a.click();
  URL.revokeObjectURL(url);
}
