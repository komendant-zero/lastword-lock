/**
 * Web Miner Manager & Pool Telemetry Client.
 * Orchestrates multi-threaded Web Workers, job leasing, and live dashboard.
 */

class WebMinerApp {
  constructor() {
    this.workerId = "web_" + Math.random().toString(36).substring(2, 10);
    this.deviceName = this.detectDeviceName();
    this.deviceType = this.detectDeviceType();

    this.maxThreads = navigator.hardwareConcurrency || 4;
    this.activeThreads = Math.max(1, Math.min(this.maxThreads, 4));

    this.isMining = false;
    this.workers = [];
    this.workerStates = []; // { busy, jobId, hashesDone }

    this.puzzleInfo = null;
    this.saltWords = new Uint32Array(4);
    this.targetWords = new Uint32Array(8);

    // Hashrate tracking
    this.totalLocalHashes = 0;
    this.sessionHashes = 0;
    this.lastHashSample = 0;
    this.lastSampleTime = performance.now();
    this.localHashrate = 0;

    // WebSocket / Polling
    this.ws = null;
    this.isSolved = false;

    this.initElements();
    this.bindEvents();
    this.loadPuzzleInfo();
  }

  detectDeviceType() {
    const ua = navigator.userAgent;
    if (/android/i.test(ua)) return "android";
    if (/iPad|iPhone|iPod/.test(ua)) return "ios";
    return "browser";
  }

  detectDeviceName() {
    const type = this.detectDeviceType();
    if (type === "ios") return "Mobile Safari (Apple)";
    if (type === "android") return "Mobile Chrome (Android)";
    if (/macintosh|mac os x/i.test(navigator.userAgent)) return "Browser (macOS)";
    if (/windows/i.test(navigator.userAgent)) return "Browser (Windows)";
    return "Web Client (" + (navigator.hardwareConcurrency || "4") + "c)";
  }

  initElements() {
    this.elFileName = document.getElementById("file-name");
    this.elFileSize = document.getElementById("file-size");
    this.elDifficulty = document.getElementById("difficulty");
    this.elSearchSpace = document.getElementById("search-space");

    this.elLocalHashrate = document.getElementById("local-hashrate");
    this.elPoolHashrate = document.getElementById("pool-hashrate");
    this.elEstimatedTime = document.getElementById("estimated-time");

    this.elProgressBar = document.getElementById("progress-bar");
    this.elProgressPct = document.getElementById("progress-pct");
    this.elProgressDone = document.getElementById("progress-done");
    this.elProgressTotal = document.getElementById("progress-total");

    this.elAlgorithm = document.getElementById("algorithm");
    this.elThreadSlider = document.getElementById("thread-slider");
    this.elThreadCount = document.getElementById("thread-count");
    this.elBtnToggleMine = document.getElementById("btn-toggle-mine");

    this.elWorkersTable = document.getElementById("workers-table-body");
    this.elVictoryModal = document.getElementById("victory-modal");
    this.elVictoryNonce = document.getElementById("victory-nonce");
    this.elVictoryWinner = document.getElementById("victory-winner");
    this.elBtnDownload = document.getElementById("btn-download");

    this.elThreadSlider.max = this.maxThreads;
    this.elThreadSlider.value = this.activeThreads;
    this.elThreadCount.textContent = this.activeThreads;
  }

  bindEvents() {
    this.elThreadSlider.addEventListener("input", (e) => {
      this.activeThreads = parseInt(e.target.value, 10);
      this.elThreadCount.textContent = this.activeThreads;
      if (this.isMining) {
        this.restartWorkers();
      }
    });

    this.elBtnToggleMine.addEventListener("click", () => {
      if (this.isMining) {
        this.stopMining();
      } else {
        this.startMining();
      }
    });

    setInterval(() => this.updateHashrate(), 1000);
  }

  async loadPuzzleInfo() {
    try {
      const res = await fetch("/api/info");
      const data = await res.json();
      this.puzzleInfo = data;

      this.elFileName.textContent = data.filename;
      this.elFileSize.textContent = this.formatBytes(data.file_size);
      this.elDifficulty.textContent = data.difficulty + " bits";
      this.elSearchSpace.textContent = data.search_space.toLocaleString();
      if (this.elAlgorithm) {
        this.elAlgorithm.textContent = (data.pow_alg || "sha256").toUpperCase();
      }

      if (data.contest_mode) {
        const badge = document.querySelector(".brand-badge");
        if (badge) {
          badge.textContent = "CONTEST MODE";
          badge.style.borderColor = "var(--accent-amber)";
          badge.style.color = "var(--accent-amber)";
          badge.style.background = "rgba(245, 158, 11, 0.15)";
        }
      }

      if (data.pow_alg === "scrypt") {
        if (this.elBtnToggleMine) {
          this.elBtnToggleMine.disabled = true;
          this.elBtnToggleMine.innerHTML = `<svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg> Scrypt (Use CLI Worker)`;
          this.elBtnToggleMine.style.opacity = "0.5";
          this.elBtnToggleMine.style.cursor = "not-allowed";
        }
        const notice = document.getElementById("scrypt-notice");
        if (notice) {
          notice.style.display = "block";
        }
      }

      this.parseHexConstants(data.salt, data.target_hash);

      if (data.is_solved) {
        this.handleSolved(data.solution, data.solved_by);
      } else {
        this.connectWebSocket();
      }
    } catch (err) {
      console.error("Failed to load puzzle info:", err);
    }
  }

  parseHexConstants(saltHex, targetHex) {
    // 16 bytes salt = 4 32-bit words
    for (let i = 0; i < 4; i++) {
      this.saltWords[i] = parseInt(saltHex.substr(i * 8, 8), 16);
    }
    // 32 bytes target = 8 32-bit words
    for (let i = 0; i < 8; i++) {
      this.targetWords[i] = parseInt(targetHex.substr(i * 8, 8), 16);
    }
  }

  startMining() {
    if (this.isSolved || this.isMining) return;
    this.isMining = true;
    this.elBtnToggleMine.textContent = "Pause Mining";
    this.elBtnToggleMine.classList.remove("btn-primary");
    this.elBtnToggleMine.classList.add("btn-stop");

    this.spawnWorkers();
    this.dispatchJobs();
  }

  stopMining() {
    this.isMining = false;
    this.elBtnToggleMine.textContent = "Start Mining";
    this.elBtnToggleMine.classList.remove("btn-stop");
    this.elBtnToggleMine.classList.add("btn-primary");

    for (const w of this.workers) {
      w.postMessage({ type: "STOP" });
      w.terminate();
    }
    this.workers = [];
    this.workerStates = [];
    this.localHashrate = 0;
    this.elLocalHashrate.textContent = "0.0 H/s";
  }

  restartWorkers() {
    this.stopMining();
    this.startMining();
  }

  spawnWorkers() {
    this.workers = [];
    this.workerStates = [];

    for (let i = 0; i < this.activeThreads; i++) {
      const worker = new Worker("/static/worker.js");
      worker.postMessage({
        type: "INIT",
        saltWords: Array.from(this.saltWords),
        targetWords: Array.from(this.targetWords),
      });

      const workerIndex = i;
      this.workerStates.push({ busy: false, jobId: null, hashesDone: 0 });

      worker.onmessage = (e) => this.handleWorkerMessage(workerIndex, e.data);
      this.workers.push(worker);
    }
  }

  async dispatchJobs() {
    if (!this.isMining || this.isSolved) return;

    for (let i = 0; i < this.workers.length; i++) {
      if (!this.workerStates[i].busy) {
        this.fetchAndAssignJob(i);
      }
    }
  }

  async fetchAndAssignJob(workerIndex) {
    if (!this.isMining || this.isSolved) return;
    this.workerStates[workerIndex].busy = true;

    try {
      const url = `/api/job?worker_id=${encodeURIComponent(this.workerId)}&name=${encodeURIComponent(this.deviceName)}&device=${encodeURIComponent(this.deviceType)}&cores=${this.activeThreads}`;
      const res = await fetch(url);
      const job = await res.json();

      if (job.status === "solved") {
        this.handleSolved(job.solution, job.solved_by);
        return;
      }

      if (job.status !== "work") {
        // Wait briefly if no work
        setTimeout(() => {
          this.workerStates[workerIndex].busy = false;
          this.dispatchJobs();
        }, 1000);
        return;
      }

      this.workerStates[workerIndex].jobId = job.lease_id;
      this.workerStates[workerIndex].hashesDone = 0;

      this.workers[workerIndex].postMessage({
        type: "MINE",
        jobId: job.lease_id,
        start: job.start,
        end: job.end,
        step: 25000,
      });
    } catch (err) {
      console.error("Error fetching job:", err);
      setTimeout(() => {
        this.workerStates[workerIndex].busy = false;
        this.dispatchJobs();
      }, 2000);
    }
  }

  async handleWorkerMessage(workerIndex, msg) {
    if (msg.type === "PROGRESS") {
      this.totalLocalHashes += msg.count;
      this.sessionHashes += msg.count;
      this.workerStates[workerIndex].hashesDone += msg.count;
    } else if (msg.type === "FOUND") {
      console.log("🌟 WINNING NONCE FOUND BY THIS BROWSER:", msg.nonce);
      this.submitSolution(msg.nonce);
    } else if (msg.type === "DONE" || msg.type === "STOPPED") {
      const leaseId = this.workerStates[workerIndex].jobId;
      const doneCount = this.workerStates[workerIndex].hashesDone;
      this.workerStates[workerIndex].busy = false;

      // Report lease completion to pool
      if (leaseId) {
        this.reportProgress(leaseId, doneCount);
      }

      // Grab next job
      if (this.isMining && !this.isSolved) {
        this.fetchAndAssignJob(workerIndex);
      }
    }
  }

  async reportProgress(leaseId, hashesDone) {
    try {
      await fetch("/api/progress", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          worker_id: this.workerId,
          lease_id: leaseId,
          hashes_done: hashesDone,
          hashrate: this.localHashrate,
          name: this.deviceName,
        }),
      });
    } catch (e) {
      // Non-critical
    }
  }

  async computeSha256(str) {
    const enc = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest("SHA-256", enc);
    const hashArray = Array.from(new Uint8Array(hashBuf));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async submitSolution(nonce) {
    try {
      // 1. Commit-reveal: Send pre-commitment sha256(nonce:workerId) to defeat HTTP front-running
      try {
        const commitHash = await this.computeSha256(`${nonce}:${this.workerId}`);
        await fetch("/api/commit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            worker_id: this.workerId,
            commit: commitHash,
          }),
        });
      } catch (e) {
        console.warn("Pre-commit failed, proceeding to reveal:", e);
      }

      // 2. Submit solution
      const res = await fetch("/api/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          worker_id: this.workerId,
          name: this.deviceName,
          nonce: nonce,
        }),
      });
      const data = await res.json();
      if (data.status === "ok") {
        this.claimToken = data.claim_token;
        this.handleSolved(nonce, this.deviceName);
      }
    } catch (err) {
      console.error("Submission error:", err);
    }
  }

  updateHashrate() {
    const now = performance.now();
    const dt = (now - this.lastSampleTime) / 1000;
    if (dt >= 0.8) {
      const dHashes = this.sessionHashes - this.lastHashSample;
      this.localHashrate = Math.round(dHashes / dt);
      this.lastHashSample = this.sessionHashes;
      this.lastSampleTime = now;
      this.elLocalHashrate.textContent = this.formatHashrate(this.localHashrate);
    }
  }

  connectWebSocket() {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${location.host}/ws`;

    try {
      this.ws = new WebSocket(wsUrl);
      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        this.renderStats(data);
      };
      this.ws.onclose = () => {
        // Fallback to polling if WebSocket disconnects
        setTimeout(() => this.connectWebSocket(), 3000);
      };
    } catch (e) {
      setInterval(() => this.pollStats(), 2000);
    }
  }

  async pollStats() {
    try {
      const res = await fetch("/api/stats");
      const data = await res.json();
      this.renderStats(data);
    } catch (e) {}
  }

  renderStats(stats) {
    if (stats.is_solved) {
      this.handleSolved(stats.solution, stats.solved_by);
      return;
    }

    const poolRate = stats.pool_hashrate || 0;
    this.elPoolHashrate.textContent = this.formatHashrate(poolRate);

    // Progress bar
    const pct = stats.progress_percent || 0;
    this.elProgressBar.style.width = pct + "%";
    this.elProgressPct.textContent = pct.toFixed(1) + "%";
    this.elProgressDone.textContent = (stats.completed_hashes || 0).toLocaleString();
    this.elProgressTotal.textContent = (stats.search_space || 0).toLocaleString();

    // ETA
    const remaining = (stats.search_space || 0) - (stats.completed_hashes || 0);
    if (poolRate > 0 && remaining > 0) {
      const etaSeconds = remaining / poolRate;
      this.elEstimatedTime.textContent = this.formatSeconds(etaSeconds);
    } else {
      this.elEstimatedTime.textContent = "--";
    }

    // Workers table
    if (stats.active_workers && Array.isArray(stats.active_workers)) {
      this.renderWorkersTable(stats.active_workers);
    }
  }

  renderWorkersTable(workers) {
    this.elWorkersTable.innerHTML = "";
    for (const w of workers) {
      const tr = document.createElement("tr");

      const icon = w.device === "ios" || w.device === "android" ? "📱" : w.device === "cli" ? "💻" : "🌐";
      const isMe = w.id === this.workerId;
      const nameText = `${icon} ${w.name} ${isMe ? "(This Device)" : ""}`;

      tr.innerHTML = `
        <td class="device-name">${nameText} <span class="device-tag">${w.device}</span></td>
        <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 700;">${this.formatHashrate(w.hashrate)}</td>
        <td style="font-family: var(--font-mono); color: var(--text-muted);">${(w.hashes || 0).toLocaleString()}</td>
      `;
      this.elWorkersTable.appendChild(tr);
    }
  }

  handleSolved(nonce, winner) {
    if (this.isSolved) return;
    this.isSolved = true;
    this.stopMining();

    this.playVictoryFanfare();

    const isContest = this.puzzleInfo && this.puzzleInfo.contest_mode;
    this.elVictoryNonce.textContent = (isContest && !this.claimToken) ? "Protected (Contest Mode)" : (nonce || "--");
    this.elVictoryWinner.textContent = winner || "Unknown Device";
    this.elVictoryModal.classList.add("active");

    if (isContest && !this.claimToken) {
      this.elBtnDownload.textContent = "Contest Mode: Solved by " + (winner || "another device");
      this.elBtnDownload.disabled = true;
      this.elBtnDownload.style.opacity = "0.5";
    } else {
      this.elBtnDownload.disabled = false;
      this.elBtnDownload.style.opacity = "1";
      this.elBtnDownload.onclick = () => {
        const url = "/api/download" + (this.claimToken ? "?token=" + encodeURIComponent(this.claimToken) : "");
        window.location.href = url;
      };
    }
  }

  playVictoryFanfare() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const notes = [523.25, 659.25, 783.99, 1046.5]; // C5, E5, G5, C6
      notes.forEach((freq, idx) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "triangle";
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.15, ctx.currentTime + idx * 0.12);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + idx * 0.12 + 0.4);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(ctx.currentTime + idx * 0.12);
        osc.stop(ctx.currentTime + idx * 0.12 + 0.4);
      });
    } catch (e) {}
  }

  formatHashrate(h) {
    if (h < 1e3) return h.toFixed(0) + " H/s";
    if (h < 1e6) return (h / 1e3).toFixed(1) + " KH/s";
    if (h < 1e9) return (h / 1e6).toFixed(2) + " MH/s";
    return (h / 1e9).toFixed(2) + " GH/s";
  }

  formatSeconds(sec) {
    if (sec <= 0) return "0s";
    if (sec < 60) return Math.round(sec) + "s";
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    if (m < 60) return `${m}m ${s}s`;
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return `${h}h ${rm}m`;
  }

  formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.app = new WebMinerApp();
});
