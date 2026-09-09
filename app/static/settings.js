(() => {
  if (typeof viewTitles !== "undefined") viewTitles.settings = "Settings";

  const byId = (id) => document.getElementById(id);
  const setupPanel = byId("settingsSetupPanel");
  const settingsPanel = byId("settingsPanel");
  const setupForm = byId("setupForm");
  const settingsForm = byId("settingsForm");
  const setupMessage = byId("setupMessage");
  const settingsMessage = byId("settingsMessage");
  const navButton = document.querySelector('.nav-button[data-view="settings"]');
  let settingsLoaded = false;

  function message(element, text, kind = "") {
    if (!element) return;
    element.textContent = text;
    element.className = `control-message${kind ? ` ${kind}` : ""}`;
  }

  function setValue(id, value) {
    const el = byId(id);
    if (el) el.value = value ?? "";
  }

  function setChecked(id, value) {
    const el = byId(id);
    if (el) el.checked = Boolean(value);
  }

  function renderConfig(config) {
    if (!config) return;
    const s = config.settings || {};
    setupPanel.hidden = !config.setup_required;
    settingsPanel.hidden = Boolean(config.setup_required);
    if (config.setup_required) return;

    setValue("serviceName", s.service_name);
    setChecked("settingsDotEnabled", s.dot_enabled);
    setValue("settingsDotBindHost", s.dot_bind_host || "127.0.0.1");
    setValue("settingsDotPort", s.dot_port ?? 8853);
    setValue("settingsPublicHostname", s.dot_public_hostname || "");
    setChecked("settingsFrpcEnabled", s.frpc_enabled);
    setValue("settingsFrpServerAddr", s.frp_server_addr || "");
    setValue("settingsFrpServerPort", s.frp_server_port ?? 7000);
    setValue("settingsFrpRemotePort", s.frp_remote_port ?? 853);
    setValue("settingsUpstreamTimeout", s.upstream_timeout_seconds ?? 2);
    setValue("settingsCooldown", s.resolver_cooldown_seconds ?? 15);
    setValue("settingsCooldownMax", s.resolver_cooldown_max_seconds ?? 120);
    setValue("settingsHistoryMinutes", s.history_minutes ?? 120);
    setValue("settingsFilterUpdateHours", s.filter_update_hours ?? 24);
    setValue("settingsAdminUsername", config.username || "");

    const tokenState = byId("frpTokenState");
    if (tokenState) {
      tokenState.textContent = config.secrets?.frp_auth_token_configured
        ? "A token is stored. Leave the field blank to keep it."
        : "No FRP token is stored.";
    }
    const tlsState = byId("tlsState");
    if (tlsState) {
      tlsState.textContent = config.secrets?.certificate_configured
        ? "A certificate and private key are stored. Leave both fields blank to keep them."
        : "No dashboard-managed TLS certificate is stored yet.";
    }
    const storage = byId("configStorageNote");
    if (storage) {
      const prefix = config.storage?.fallback_used
        ? "Warning: persistent data path was unavailable; using temporary storage. "
        : `Storage: ${config.storage?.root || "unknown"}. `;
      storage.textContent = prefix + (config.storage?.note || "");
      storage.className = config.storage?.fallback_used ? "storage-note warning" : "storage-note";
    }
  }

  async function loadSettings(force = false) {
    if (settingsLoaded && !force) return;
    message(settingsMessage, "Loading settings...");
    try {
      const response = await fetch("/api/settings", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (!data.ok) throw new Error(data.error || "Settings request failed.");
      renderConfig(data.config);
      settingsLoaded = true;
      message(settingsMessage, "");
    } catch (error) {
      message(settingsMessage, `Settings unavailable: ${error.message}`, "error");
    }
  }

  navButton?.addEventListener("click", () => loadSettings());

  setupForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = byId("setupUsername").value.trim();
    const password = byId("setupPassword").value;
    const confirmation = byId("setupPasswordConfirm").value;
    if (password !== confirmation) {
      message(setupMessage, "Passwords do not match.", "error");
      return;
    }
    message(setupMessage, "Creating administrator...");
    try {
      const response = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
      message(setupMessage, data.message || "Administrator created.", "success");
      setTimeout(() => window.location.reload(), 700);
    } catch (error) {
      message(setupMessage, error.message, "error");
    }
  });

  function settingsPayload() {
    const payload = {
      action: "save_settings",
      service_name: byId("serviceName").value,
      dot_enabled: byId("settingsDotEnabled").checked,
      dot_bind_host: byId("settingsDotBindHost").value,
      dot_port: byId("settingsDotPort").value,
      dot_public_hostname: byId("settingsPublicHostname").value,
      frpc_enabled: byId("settingsFrpcEnabled").checked,
      frp_server_addr: byId("settingsFrpServerAddr").value,
      frp_server_port: byId("settingsFrpServerPort").value,
      frp_remote_port: byId("settingsFrpRemotePort").value,
      upstream_timeout_seconds: byId("settingsUpstreamTimeout").value,
      resolver_cooldown_seconds: byId("settingsCooldown").value,
      resolver_cooldown_max_seconds: byId("settingsCooldownMax").value,
      history_minutes: byId("settingsHistoryMinutes").value,
      filter_update_hours: byId("settingsFilterUpdateHours").value,
      admin_username: byId("settingsAdminUsername").value.trim(),
      clear_frp_auth_token: byId("clearFrpAuthToken").checked,
    };
    const token = byId("settingsFrpAuthToken").value;
    const certificate = byId("settingsTlsCertificate").value;
    const privateKey = byId("settingsTlsPrivateKey").value;
    const newPassword = byId("settingsAdminPassword").value;
    if (token) payload.frp_auth_token = token;
    if (certificate || privateKey) {
      payload.certificate_pem = certificate;
      payload.private_key_pem = privateKey;
    }
    if (newPassword) payload.new_password = newPassword;
    return payload;
  }

  async function saveOrImport(payload) {
    const response = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  settingsForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const certificate = byId("settingsTlsCertificate").value.trim();
    const privateKey = byId("settingsTlsPrivateKey").value.trim();
    if (Boolean(certificate) !== Boolean(privateKey)) {
      message(settingsMessage, "Certificate and private key must be supplied together.", "error");
      return;
    }
    byId("saveSettingsButton").disabled = true;
    message(settingsMessage, "Saving settings...");
    try {
      const data = await saveOrImport(settingsPayload());
      message(settingsMessage, data.message || "Settings saved.", "success");
      setTimeout(() => window.location.reload(), data.restart_scheduled ? 1800 : 400);
    } catch (error) {
      message(settingsMessage, error.message, "error");
      byId("saveSettingsButton").disabled = false;
    }
  });

  byId("exportBackupButton")?.addEventListener("click", async () => {
    message(settingsMessage, "Preparing encrypted-secrets-sensitive backup...");
    try {
      const response = await fetch("/api/settings/export", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const anchor = document.createElement("a");
      anchor.href = URL.createObjectURL(blob);
      anchor.download = `dns-dashboard-backup-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(anchor.href);
      message(settingsMessage, "Backup exported. It contains sensitive secrets; store it securely.", "success");
    } catch (error) {
      message(settingsMessage, error.message, "error");
    }
  });

  byId("importBackupInput")?.addEventListener("change", async () => {
    const input = byId("importBackupInput");
    const file = input.files?.[0];
    if (!file) return;
    if (!window.confirm("Import this backup and restart the DNS service? Existing dashboard settings and profiles will be replaced.")) {
      input.value = "";
      return;
    }
    message(settingsMessage, "Importing backup...");
    try {
      const backup = JSON.parse(await file.text());
      const data = await saveOrImport({ action: "import_backup", backup });
      message(settingsMessage, data.message || "Backup imported.", "success");
      setTimeout(() => window.location.reload(), data.restart_scheduled ? 1800 : 400);
    } catch (error) {
      message(settingsMessage, error.message, "error");
    } finally {
      input.value = "";
    }
  });

  // First-run users need Settings surfaced immediately; existing installations
  // can load it lazily when the Settings tab is opened.
  fetch("/api/settings", { cache: "no-store" })
    .then((response) => (response.ok ? response.json() : null))
    .then((data) => {
      if (data?.ok && data.config?.setup_required) {
        settingsLoaded = true;
        renderConfig(data.config);
        if (typeof navigate === "function") navigate("settings");
      }
    })
    .catch(() => {});
})();
