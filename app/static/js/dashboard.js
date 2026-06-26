/* TICluster dashboard */
(function () {
  "use strict";

  let campaigns = [];
  let activeCampaignId = null;

  // ── Helpers ───────────────────────────────────────────────

  function confColor(score) {
    if (score >= 0.65) return "var(--high)";
    if (score >= 0.50) return "var(--medium)";
    return "var(--muted)";
  }

  function confLevel(score) {
    if (score >= 0.65) return "high";
    if (score >= 0.50) return "medium";
    return "low";
  }

  function escHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // ── Stats bar ─────────────────────────────────────────────

  async function loadStats() {
    try {
      const res  = await fetch("/api/stats");
      const data = await res.json();
      document.getElementById("stat-iocs").textContent      = data.total_iocs      ?? "—";
      document.getElementById("stat-campaigns").textContent = data.total_campaigns  ?? "—";
      document.getElementById("stat-high").textContent      = data.high_confidence  ?? "—";
      document.getElementById("stat-noise").textContent     = data.noise_iocs       ?? "—";
    } catch (e) {
      console.error("Stats load failed", e);
    }
  }

  // ── Campaign list ─────────────────────────────────────────

  async function loadCampaigns() {
    const res = await fetch("/api/campaigns");
    campaigns = await res.json();
    renderList(campaigns);
  }

  function renderList(list) {
    const ul = document.getElementById("campaign-list");
    ul.innerHTML = "";

    list.forEach(c => {
      const level = confLevel(c.confidence);
      const li = document.createElement("li");
      li.dataset.id = c.id;
      if (c.id === activeCampaignId) li.classList.add("active");

      li.innerHTML = `
        <span class="campaign-name">${escHtml(c.name)}</span>
        <div class="campaign-meta">
          <span class="badge ${level}">${level}</span>
          <div class="conf-bar-wrap">
            <div class="conf-bar"
                 style="width:${(c.confidence * 100).toFixed(1)}%;
                        background:${confColor(c.confidence)}"></div>
          </div>
          <span class="conf-val">${c.confidence.toFixed(3)}</span>
        </div>`;

      li.addEventListener("click", () => selectCampaign(c.id));
      ul.appendChild(li);
    });
  }

  // ── Search ────────────────────────────────────────────────

  document.getElementById("search").addEventListener("input", function () {
    const q = this.value.toLowerCase();
    const filtered = campaigns.filter(c =>
      c.name.toLowerCase().includes(q) ||
      (c.primary_asn  || "").toLowerCase().includes(q) ||
      (c.malware_families || []).join(" ").toLowerCase().includes(q)
    );
    renderList(filtered);
  });

  // ── Campaign detail ───────────────────────────────────────

  async function selectCampaign(id) {
    activeCampaignId = id;

    // Highlight sidebar
    document.querySelectorAll("#campaign-list li").forEach(li => {
      li.classList.toggle("active", Number(li.dataset.id) === id);
    });

    // Fetch detail (includes iocs)
    const res      = await fetch(`/api/campaigns/${id}`);
    const campaign = await res.json();

    renderDetail(campaign);
    showTab("iocs");

    // Load sigma lazily
    document.getElementById("sigma-code").textContent = "Loading…";
    fetch(`/api/campaigns/${id}/sigma`)
      .then(r => r.text())
      .then(yaml => {
        document.getElementById("sigma-code").textContent = yaml;
      })
      .catch(() => {
        document.getElementById("sigma-code").textContent = "No Sigma rule available.";
      });
  }

  function renderDetail(campaign) {
    const level = confLevel(campaign.confidence);

    document.getElementById("detail-name").textContent = campaign.name;
    document.getElementById("detail-level").textContent = level;
    document.getElementById("detail-level").className = `badge ${level}`;
    document.getElementById("detail-confidence").textContent =
      `Confidence: ${(campaign.confidence * 100).toFixed(1)}%`;
    document.getElementById("detail-ioc-count").textContent =
      `${campaign.ioc_count} IOCs`;
    document.getElementById("detail-country").textContent =
      campaign.primary_country ? `🌐 ${campaign.primary_country}` : "";
    document.getElementById("detail-asn").textContent =
      campaign.primary_asn ? `ASN ${campaign.primary_asn}` : "";
    document.getElementById("detail-basis").textContent =
      campaign.basis || "";

    // IOC table
    const tbody = document.getElementById("ioc-tbody");
    tbody.innerHTML = "";
    (campaign.iocs || []).forEach(ioc => {
      const tr = document.createElement("tr");
      const typeClass = `type-${ioc.ioc_type}`;
      tr.innerHTML = `
        <td><span class="type-badge ${typeClass}">${escHtml(ioc.ioc_type)}</span></td>
        <td><span class="ioc-value">${escHtml(ioc.value)}</span></td>
        <td>${escHtml(ioc.malware_family || "—")}</td>
        <td>${escHtml(ioc.country || "—")}</td>
        <td style="font-family:var(--font-mono);font-size:11px">${escHtml(ioc.asn || "—")}</td>
        <td>${escHtml(ioc.source || "—")}</td>`;
      tbody.appendChild(tr);
    });

    document.getElementById("detail-empty").hidden   = true;
    document.getElementById("detail-content").hidden = false;
  }

  // ── Tabs ──────────────────────────────────────────────────

  function showTab(name) {
    document.querySelectorAll(".tab").forEach(t => {
      t.classList.toggle("active", t.dataset.tab === name);
    });
    document.getElementById("tab-iocs").hidden  = (name !== "iocs");
    document.getElementById("tab-sigma").hidden = (name !== "sigma");
  }

  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => showTab(btn.dataset.tab));
  });

  // ── Copy Sigma ────────────────────────────────────────────

  document.getElementById("copy-sigma").addEventListener("click", () => {
    const text = document.getElementById("sigma-code").textContent;
    navigator.clipboard.writeText(text).then(() => {
      const confirm = document.getElementById("copy-confirm");
      confirm.hidden = false;
      setTimeout(() => { confirm.hidden = true; }, 2000);
    });
  });

  // ── Init ──────────────────────────────────────────────────

  loadStats();
  loadCampaigns();

})();