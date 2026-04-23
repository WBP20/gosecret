import { importKey, decryptText, b64d, b64urlDecode } from "/static/crypto.js";

const loading = document.getElementById("loading");
const errCard = document.getElementById("err");
const questionCard = document.getElementById("questionCard");
const consumeCard = document.getElementById("consumeCard");
const revealCard = document.getElementById("revealCard");
const revealed = document.getElementById("revealed");

function showError(msg) {
  loading.classList.add("hidden");
  questionCard.classList.add("hidden");
  consumeCard.classList.add("hidden");
  errCard.textContent = msg;
  errCard.classList.remove("hidden");
}

function idFromPath() {
  const parts = window.location.pathname.split("/");
  return parts[parts.length - 1];
}

function keyFromFragment() {
  const frag = window.location.hash.replace(/^#/, "");
  if (!frag) return null;
  try { return b64urlDecode(frag); } catch { return null; }
}

async function decryptAndReveal(rawKey, ciphertextB64, ivB64) {
  let key;
  try {
    key = await importKey(rawKey);
  } finally {
    rawKey.fill(0);
  }
  const plaintext = await decryptText(key, b64d(ciphertextB64), b64d(ivB64));
  revealed.textContent = plaintext;
  loading.classList.add("hidden");
  questionCard.classList.add("hidden");
  consumeCard.classList.add("hidden");
  revealCard.classList.remove("hidden");
  document.getElementById("copySecret").onclick = async () => {
    const btn = document.getElementById("copySecret");
    try {
      await navigator.clipboard.writeText(plaintext);
      btn.textContent = "copied ✓";
      setTimeout(() => { btn.textContent = "copy"; }, 1500);
    } catch {
      btn.textContent = "copy failed";
      btn.style.borderColor = "var(--red)";
      btn.style.color = "var(--red)";
    }
  };
  history.replaceState(null, "", window.location.pathname);
}

async function main() {
  const id = idFromPath();
  const rawKey = keyFromFragment();
  if (!rawKey) { showError("missing key in url#fragment"); return; }
  if (rawKey.length !== 32) { showError("invalid key length — link may be truncated"); return; }

  let meta;
  try {
    const res = await fetch(`/api/secrets/${encodeURIComponent(id)}`);
    if (res.status === 404) { showError("not found / expired / already read"); return; }
    if (!res.ok) { showError("server error"); return; }
    meta = await res.json();
  } catch { showError("network error"); return; }

  if (meta.consumed) { showError("already read & destroyed"); return; }
  if (meta.expired)  { showError("expired"); return; }
  if (meta.locked)   { showError("locked — too many failed attempts"); return; }

  loading.classList.add("hidden");

  if (meta.has_question) {
    document.getElementById("questionText").textContent = meta.question || "(challenge)";
    document.getElementById("attemptsMeta").textContent = `${meta.remaining_attempts} tries left`;
    questionCard.classList.remove("hidden");
    document.getElementById("unlockForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = document.getElementById("unlockBtn");
      btn.disabled = true;
      try {
        const answer = document.getElementById("answer").value;
        const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/unlock`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ answer }),
        });
        if (res.status === 401) {
          const j = await res.json().catch(() => ({}));
          const remaining = j.remaining_attempts ?? "?";
          if (remaining === 0) {
            showError("locked — too many failed attempts");
          } else {
            document.getElementById("attemptsMeta").textContent = `wrong. ${remaining} tries left`;
          }
          return;
        }
        if (!res.ok) {
          const j = await res.json().catch(() => ({}));
          showError(j.message || "unlock failed");
          return;
        }
        const j = await res.json();
        await decryptAndReveal(rawKey, j.ciphertext, j.iv);
      } catch (err) {
        showError(err.message || String(err));
      } finally {
        btn.disabled = false;
      }
    });
  } else {
    consumeCard.classList.remove("hidden");
    document.getElementById("consumeBtn").onclick = async () => {
      const btn = document.getElementById("consumeBtn");
      btn.disabled = true;
      try {
        const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/consume`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        if (!res.ok) {
          const j = await res.json().catch(() => ({}));
          showError(j.message || "reveal failed");
          return;
        }
        const j = await res.json();
        await decryptAndReveal(rawKey, j.ciphertext, j.iv);
      } catch (err) {
        showError(err.message || String(err));
      } finally {
        btn.disabled = false;
      }
    };
  }
}

main();
