async function runVulnScan() {
  const url = document.getElementById("target").value.trim();
  const output = document.getElementById("output");

  if (!url) {
    alert("URL girmeniz gerekiyor.");
    return;
  }

  output.innerHTML = "<p>⏳ Taranıyor...</p>";

  try {
    const res = await fetch(`/api/vulnscan?url=${encodeURIComponent(url)}`);
    const data = await res.json();

    if (data.error) {
      output.innerHTML = `<p style="color:red;">Hata: ${data.error}</p>`;
      return;
    }

    let html = "<h3>Sonuçlar:</h3><pre>";
    html += `SQL Injection: ${data.sql_injection ? "⚠️ Zafiyet" : "✅ Güvenli"}\n`;
    html += `XSS: ${data.xss ? "⚠️ Zafiyet" : "✅ Güvenli"}\n`;
    html += `Open Redirect: ${data.open_redirect ? "⚠️ Zafiyet" : "✅ Güvenli"}\n`;
    html += `WAF: ${data.waf ? "🛡️ Aktif" : "❌ Tespit Edilmedi"}\n`;
    html += "</pre>";

    output.innerHTML = html;
  } catch (e) {
    output.innerHTML = `<p style="color:red;">Sunucu hatası: ${e.message}</p>`;
  }
}
