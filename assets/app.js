(function () {
  const copyButtons = document.querySelectorAll("[data-copy]");
  copyButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copy);
      if (!target) return;
      await navigator.clipboard.writeText(target.innerText || target.value || "");
      const old = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = old), 1200);
    });
  });

  document.querySelectorAll("[data-confirm]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (!confirm(button.dataset.confirm)) event.preventDefault();
    });
  });

  const languageSelect = document.querySelector("#language");
  const content = document.querySelector("#content");
  if (languageSelect && content) {
    languageSelect.addEventListener("change", () => {
      content.dataset.language = languageSelect.value;
    });
  }

  const themeToggle = document.querySelector("[data-theme-toggle]");
  if (themeToggle) {
    themeToggle.addEventListener("click", (event) => {
      event.preventDefault();
      const next = document.body.dataset.theme === "dark" ? "light" : "dark";
      document.body.dataset.theme = next;
      document.cookie = `theme=${next}; Max-Age=31536000; Path=/; SameSite=Lax`;
      themeToggle.textContent = next === "dark" ? "Light mode" : "Dark mode";
    });
  }

  const capacitor = window.Capacitor;
  const biometrics = capacitor?.Plugins?.PastenatorBiometrics;
  const appInfo = capacitor?.Plugins?.PastenatorAppInfo;
  const isNative = Boolean(capacitor?.isNativePlatform?.() || biometrics || appInfo);
  const isSignedIn = document.body.dataset.signedIn === "1";
  const lockKey = "pastenatorMobileLockEnabled";
  const unlockKey = "pastenatorUnlockedAt";
  const hiddenKey = "pastenatorHiddenAt";
  const relockMs = 2 * 60 * 1000;

  const openAppstore = async () => {
    try {
      if (appInfo?.openAppstore) {
        await appInfo.openAppstore();
        return;
      }
    } catch (error) {
      // Browser fallback below.
    }
    window.location.href = "intent://appstore.quantumnet.space/#Intent;scheme=https;package=com.myname.mystore;S.browser_fallback_url=https%3A%2F%2Fappstore.quantumnet.space%2F;end";
  };

  const showUpdatePrompt = (installed, available) => {
    const key = `pastenatorUpdatePrompt:${available.versionCode}`;
    try {
      if (sessionStorage.getItem(key)) return false;
      sessionStorage.setItem(key, "1");
    } catch (error) {
      // If storage is blocked, showing the prompt is still harmless.
    }

    const shell = document.createElement("div");
    shell.className = "app-update-popup";
    shell.innerHTML = '<div class="app-update-card" role="alertdialog" aria-live="polite"><img src="assets/logo.svg" alt=""><p class="alert-kicker">Update available</p><h2>Pastenator update available</h2><p class="muted"></p><div class="btn-row"><button type="button" data-update-now>Open Quantum Appstore</button><button class="secondary" type="button" data-update-later>Later</button></div></div>';
    const detail = shell.querySelector(".muted");
    if (detail) detail.textContent = `Installed ${installed.versionName || installed.versionCode}. Available ${available.versionName}.`;
    shell.querySelector("[data-update-later]")?.addEventListener("click", () => shell.remove());
    shell.querySelector("[data-update-now]")?.addEventListener("click", async () => {
      await openAppstore();
      shell.remove();
    });
    document.body.appendChild(shell);
    window.setTimeout(() => shell.classList.add("show"), 30);
    return true;
  };

  const checkForAppUpdate = async () => {
    if (!isNative) return;
    try {
      const response = await fetch("https://appstore.quantumnet.space/api/apps.json?t=" + Date.now(), { cache: "no-store" });
      if (!response.ok) return;
      const catalogue = await response.json();
      const installed = appInfo?.getInfo
        ? await appInfo.getInfo()
        : { packageName: "com.myname.pastenator", versionName: "older app", versionCode: 0 };
      const app = (catalogue.apps || []).find((item) => item.package_name === installed.packageName);
      if (!app || Number(app.version_code) <= Number(installed.versionCode || 0)) return;
      const shown = showUpdatePrompt(installed, { versionName: app.version, versionCode: app.version_code });
      if (shown && appInfo?.notifyUpdateAvailable) {
        try {
          await appInfo.notifyUpdateAvailable({
            id: 99000 + (Number(app.version_code) % 1000),
            title: "Pastenator update available",
            body: `Version ${app.version} is ready in Quantum Appstore.`
          });
        } catch (error) {
          // The in-app update prompt remains visible if native notifications are disabled.
        }
      }
    } catch (error) {
      // Update checks should never block Pastenator.
    }
  };

  checkForAppUpdate();
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) checkForAppUpdate();
  });
  window.setInterval(checkForAppUpdate, 6 * 60 * 60 * 1000);

  if (isNative) {
    if (isSignedIn) {
      localStorage.setItem(lockKey, "1");
    } else {
      localStorage.removeItem(lockKey);
      sessionStorage.removeItem(unlockKey);
    }
  }

  function lockOverlay(message = "Use fingerprint or device unlock to open Pastenator.") {
    let overlay = document.querySelector("[data-native-lock]");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.className = "native-lock";
      overlay.dataset.nativeLock = "true";
      overlay.innerHTML = '<div class="native-lock-card"><img src="assets/logo.svg" alt=""><h2>Unlock Pastenator</h2><p></p><button type="button">Unlock</button></div>';
      document.body.appendChild(overlay);
      overlay.querySelector("button").addEventListener("click", () => unlock(true));
    }
    overlay.querySelector("p").textContent = message;
    overlay.hidden = false;
    return overlay;
  }

  async function unlock(force = false) {
    if (!isNative || !isSignedIn || localStorage.getItem(lockKey) !== "1" || !biometrics) return;
    const lastUnlock = Number(sessionStorage.getItem(unlockKey) || 0);
    if (!force && Date.now() - lastUnlock < relockMs) return;
    const overlay = lockOverlay();
    try {
      const available = await biometrics.isAvailable();
      if (!available?.available) {
        overlay.hidden = true;
        return;
      }
      await biometrics.authenticate({
        title: "Unlock Pastenator",
        subtitle: "Use fingerprint or device unlock to open Pastenator."
      });
      sessionStorage.setItem(unlockKey, String(Date.now()));
      overlay.hidden = true;
    } catch (error) {
      lockOverlay(error?.message || "Authentication was cancelled. Tap Unlock to try again.");
    }
  }

  unlock();

  document.addEventListener("visibilitychange", () => {
    if (!isNative || !isSignedIn) return;
    if (document.hidden) {
      sessionStorage.setItem(hiddenKey, String(Date.now()));
      return;
    }
    const hiddenAt = Number(sessionStorage.getItem(hiddenKey) || 0);
    if (hiddenAt && Date.now() - hiddenAt > relockMs) {
      sessionStorage.removeItem(unlockKey);
      unlock(true);
    }
  });
})();
