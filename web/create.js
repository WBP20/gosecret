import { generateKey, exportKey, encryptText, b64, b64urlEncode } from "/static/crypto.js";

const form = document.getElementById("form");
const errBox = document.getElementById("err");
const created = document.getElementById("created");
const createdUrl = document.getElementById("createdUrl");
const createdMeta = document.getElementById("createdMeta");
const submitBtn = document.getElementById("submit");
const optToggle = document.getElementById("optToggle");
const optBody = document.getElementById("optBody");

optToggle.addEventListener("click", () => {
  const open = optBody.classList.toggle("hidden") === false;
  optToggle.classList.toggle("open", open);
});

function showError(msg) { errBox.textContent = msg; errBox.classList.remove("hidden"); }
function clearError() { errBox.classList.add("hidden"); }

function val(name) {
  const el = document.querySelector(`input[name="${name}"]:checked`);
  return el ? parseInt(el.value, 10) : 0;
}

function glitchText(el, finalText, duration = 600) {
  return new Promise((resolve) => {
    const chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`0123456789abcdef";
    const len = finalText.length;
    const steps = 14;
    const interval = duration / steps;
    let step = 0;
    const id = setInterval(() => {
      step++;
      let out = "";
      for (let i = 0; i < len; i++) {
        out += (i < (step / steps) * len)
          ? finalText[i]
          : chars[Math.floor(Math.random() * chars.length)];
      }
      el.textContent = out;
      if (step >= steps) {
        clearInterval(id);
        el.textContent = finalText;
        resolve();
      }
    }, interval);
  });
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();

  const secret = document.getElementById("secret").value;
  const question = document.getElementById("question").value.trim();
  const answer = document.getElementById("answer").value.trim();
  const ttl = val("ttl") || 86400;
  const attempts = val("attempts") || 5;

  if (!secret) { showError("payload empty"); return; }
  if ((question === "") !== (answer === "")) {
    showError("challenge requires both question & answer");
    return;
  }

  submitBtn.disabled = true;
  await glitchText(submitBtn, "encrypting...", 700);
  try {
    const key = await generateKey();
    const { ciphertext, iv } = await encryptText(key, secret);
    const rawKey = await exportKey(key);

    const res = await fetch("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext: b64(ciphertext),
        iv: b64(iv),
        question, answer,
        ttl_seconds: ttl,
        max_attempts: attempts,
      }),
    });
    if (!res.ok) {
      const j = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(j.message || "server error");
    }
    const j = await res.json();
    const url = `${j.url}#${b64urlEncode(rawKey)}`;

    rawKey.fill(0);
    document.getElementById("secret").value = "";
    document.getElementById("answer").value = "";

    createdUrl.textContent = url;
    const exp = new Date(j.expires_at);
    createdMeta.textContent = `expires ${exp.toLocaleString()}`;
    form.classList.add("hidden");
    optToggle.classList.add("hidden");
    created.classList.remove("hidden");

    document.getElementById("copyBtn").onclick = async () => {
      try {
        await navigator.clipboard.writeText(url);
        const btn = document.getElementById("copyBtn");
        btn.textContent = "copied ✓";
        setTimeout(() => { btn.textContent = "copy"; }, 1500);
      } catch { showError("copy failed — select manually"); }
    };
    document.getElementById("newBtn").onclick = () => { window.location.reload(); };
  } catch (err) {
    showError(err.message || String(err));
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "encrypt \u2192";
  }
});
