(() => {
  const playground = document.querySelector("[data-playground]");
  if (!playground) return;

  const sequences = new Map(
    [...playground.querySelectorAll("[data-sequence-diagram]")].map((diagram) => [
      diagram.dataset.sequenceDiagram,
      createSequenceDiagram(diagram),
    ]),
  );

  initTabs(playground);
  initJwtTool(playground.querySelector("[data-jwt-tool]"), sequences.get("jwt"));
  initPkiLab(playground.querySelector("[data-pki-lab]"), sequences.get("pki"));
  initContractDemo(playground.querySelector("[data-contract-sim]"), sequences.get("contract"));
  initLoginLab(playground.querySelector("[data-login-lab]"), sequences.get("login"));

  function createSequenceDiagram(diagram) {
    const events = diagram.querySelector("[data-sequence-events]");
    const countLabel = diagram.querySelector("[data-sequence-count]");
    const emptyMessage = events.querySelector(".sequence-empty")?.textContent || "Waiting for activity.";
    let count = 0;

    function reset(message = emptyMessage) {
      count = 0;
      countLabel.textContent = "Waiting";
      const empty = document.createElement("li");
      empty.className = "sequence-empty";
      empty.textContent = message;
      events.replaceChildren(empty);
    }

    function trace(from, to, message, result = "success") {
      count += 1;
      events.querySelector(".sequence-empty")?.remove();
      const item = document.createElement("li");
      item.className = "sequence-event";
      item.dataset.state = result;

      const number = document.createElement("span");
      number.className = "sequence-number";
      number.textContent = String(count).padStart(2, "0");

      const hop = document.createElement("span");
      hop.className = "sequence-hop";
      const sender = document.createElement("span");
      sender.className = "sequence-sender";
      sender.textContent = from;
      const arrow = document.createElement("span");
      arrow.className = "sequence-arrow";
      arrow.setAttribute("aria-hidden", "true");
      arrow.textContent = "→";
      const receiver = document.createElement("span");
      receiver.className = "sequence-receiver";
      receiver.textContent = to;
      hop.append(sender, arrow, receiver);

      const label = document.createElement("span");
      label.className = "sequence-result";
      label.textContent = result === "error" ? "BLOCKED" : result === "challenge" ? "CHALLENGE" : "DONE";

      const detail = document.createElement("span");
      detail.className = "sequence-message";
      detail.textContent = message;
      item.append(number, hop, label, detail);
      events.append(item);
      countLabel.textContent = `${count} ${count === 1 ? "step" : "steps"}`;
      events.scrollTop = events.scrollHeight;
    }

    return { reset, trace };
  }

  function initTabs(root) {
    const tabs = [...root.querySelectorAll('[role="tab"]')];

    function activateTab(selectedIndex, moveFocus) {
      tabs.forEach((tab, index) => {
        const selected = index === selectedIndex;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        root.querySelector(`#${tab.getAttribute("aria-controls")}`).hidden = !selected;
      });
      if (moveFocus) tabs[selectedIndex].focus();
    }

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => activateTab(index, false));
      tab.addEventListener("keydown", (event) => {
        let nextIndex = index;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") nextIndex = 0;
        else if (event.key === "End") nextIndex = tabs.length - 1;
        else return;
        event.preventDefault();
        activateTab(nextIndex, true);
      });
    });
  }

  function initJwtTool(tool, sequence) {
    if (!tool) return;

    const form = tool.querySelector("[data-jwt-form]");
    const input = tool.querySelector("[data-jwt-input]");
    const status = tool.querySelector("[data-jwt-status]");
    const result = tool.querySelector("[data-jwt-result]");
    const expiry = tool.querySelector("[data-jwt-expiry]");
    const headerOutput = tool.querySelector("[data-jwt-header]");
    const payloadOutput = tool.querySelector("[data-jwt-payload]");

    function decodeObject(segment, label, sequence) {
      sequence.trace("JWT decoder", "JWT decoder", `${label}: test base64url character whitelist and padding regex`);
      if (!/^[A-Za-z0-9_-]+={0,2}$/.test(segment)) {
        throw new Error(`${label} is not valid base64url data.`);
      }

      const unpadded = segment.replace(/=+$/, "");
      const base64 = unpadded.replace(/-/g, "+").replace(/_/g, "/");
      sequence.trace("JWT decoder", "JWT decoder", `${label}: strip trailing '=' and map '-'/'_' to '+'/'/'`);
      sequence.trace("JWT decoder", "JWT decoder", `${label}: reject base64 length where length % 4 === 1`);
      if (base64.length % 4 === 1) {
        throw new Error(`${label} has an invalid base64url length.`);
      }

      const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
      sequence.trace("JWT decoder", "JWT decoder", `${label}: add '=' padding to a multiple of 4`);
      let parsed;
      try {
        sequence.trace("JWT decoder", "Base64 / UTF-8 APIs", `${label}: atob(padded) and Uint8Array.from(...charCodeAt(0))`);
        const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
        sequence.trace("Base64 / UTF-8 APIs", "JWT decoder", `${label}: return decoded Uint8Array bytes`);
        sequence.trace("JWT decoder", "Base64 / UTF-8 APIs", `${label}: TextDecoder('utf-8', {fatal:true}).decode(bytes)`);
        const jsonText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        sequence.trace("Base64 / UTF-8 APIs", "JWT decoder", `${label}: return UTF-8 JSON text`);
        sequence.trace("JWT decoder", "JSON.parse()", `${label}: JSON.parse(jsonText)`);
        parsed = JSON.parse(jsonText);
      } catch {
        throw new Error(`${label} must contain valid UTF-8 JSON.`);
      }

      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error(`${label} must be a JSON object.`);
      }
      sequence.trace("JSON.parse()", "JWT decoder", `${label}: require a top-level non-array object`);
      return parsed;
    }

    function setStatus(message, state = "") {
      status.textContent = message;
      status.dataset.state = state;
    }

    function decodeToken(token) {
      sequence.reset("Waiting to decode a compact JWT locally.");
      sequence.trace("Textarea", "JWT decoder", "Read token string; no HTTP request is made");
      const segments = token.trim().split(".");
      if (segments.length !== 3) {
        throw new Error("A compact JWT must contain three dot-separated parts.");
      }

      sequence.trace("JWT decoder", "JWT decoder", "split('.') and require exactly three segments");
      const header = decodeObject(segments[0], "Header", sequence);
      const payload = decodeObject(segments[1], "Payload", sequence);
      headerOutput.textContent = JSON.stringify(header, null, 2);
      payloadOutput.textContent = JSON.stringify(payload, null, 2);
      result.hidden = false;

      if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
        sequence.trace("JWT decoder", "JWT decoder", "Accept exp only when it is a finite number of epoch seconds");
        const expirationDate = new Date(payload.exp * 1000);
        expiry.hidden = false;
        if (Number.isNaN(expirationDate.getTime())) {
          expiry.textContent = "The exp claim is outside the supported date range.";
          expiry.dataset.state = "unknown";
        } else {
          const isExpired = expirationDate.getTime() <= Date.now();
          sequence.trace("Date.now()", "JWT decoder", `expirationDate.getTime() <= Date.now() → ${isExpired}`);
          expiry.textContent = `${isExpired ? "Expired" : "Expires"} ${expirationDate.toLocaleString()}`;
          expiry.dataset.state = isExpired ? "expired" : "active";
        }
      } else {
        sequence.trace("JWT decoder", "JWT decoder", "Skip expiry check: exp is missing or not a finite number");
        expiry.hidden = true;
        expiry.textContent = "";
        delete expiry.dataset.state;
      }

      setStatus("Header and payload decoded. Signature not verified.", "success");
      sequence.trace("JWT decoder", "UI output", "Render claims; signature is not cryptographically verified");
    }

    function encodeObject(value) {
      const bytes = new TextEncoder().encode(JSON.stringify(value));
      let binary = "";
      bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
      });
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!input.value.trim()) {
        result.hidden = true;
        setStatus("Paste a JWT or load the example first.", "error");
        input.focus();
        return;
      }
      try {
        decodeToken(input.value);
      } catch (error) {
        result.hidden = true;
        setStatus(error.message, "error");
        sequence.trace("JWT decoder", "UI output", `Reject input: ${error.message}`, "error");
      }
    });

    tool.querySelector("[data-jwt-sample]").addEventListener("click", () => {
      const now = Math.floor(Date.now() / 1000);
      const header = { alg: "HS256", typ: "JWT" };
      const payload = { sub: "demo-user", scope: ["read:profile"], iat: now, exp: now + 3600 };
      input.value = `${encodeObject(header)}.${encodeObject(payload)}.c2FtcGxlLXNpZ25hdHVyZQ`;
      decodeToken(input.value);
    });

    tool.querySelector("[data-jwt-clear]").addEventListener("click", () => {
      input.value = "";
      result.hidden = true;
      expiry.hidden = true;
      expiry.textContent = "";
      headerOutput.textContent = "";
      payloadOutput.textContent = "";
      setStatus("Paste a compact JWT, or load the example.");
      sequence.reset("Waiting for a token.");
      input.focus();
    });

    input.addEventListener("input", () => {
      result.hidden = true;
      setStatus("Token changed. Decode it again to refresh the results.");
      sequence.reset("Waiting for the updated token to be decoded.");
    });
  }

  function initPkiLab(lab, sequence) {
    if (!lab) return;

    const subtle = window.crypto && window.crypto.subtle;
    const encoder = new TextEncoder();
    const rootButton = lab.querySelector("[data-pki-create]");
    const issueButton = lab.querySelector("[data-pki-issue]");
    const signButton = lab.querySelector("[data-pki-sign]");
    const verifyButton = lab.querySelector("[data-pki-verify]");
    const tamperButton = lab.querySelector("[data-pki-tamper]");
    const messageInput = lab.querySelector("[data-pki-message]");
    const checks = lab.querySelector("[data-pki-checks]");
    const rootStatus = lab.querySelector("[data-pki-root-status]");
    const certificateStatus = lab.querySelector("[data-pki-certificate-status]");
    const messageStatus = lab.querySelector("[data-pki-message-status]");
    const state = { root: null, identity: null, messageSignature: null, signedMessage: "", busy: false };

    if (!subtle) {
      rootButton.disabled = true;
      rootStatus.textContent = "Web Crypto is unavailable. Use a secure browser context (HTTPS or localhost).";
      return;
    }

    function updateButtons() {
      rootButton.disabled = state.busy;
      issueButton.disabled = state.busy || !state.root;
      signButton.disabled = state.busy || !state.identity;
      verifyButton.disabled = state.busy || !state.messageSignature;
      tamperButton.disabled = state.busy || !state.messageSignature;
    }

    async function runAction(action, onError) {
      state.busy = true;
      updateButtons();
      try {
        await action();
      } catch (error) {
        onError.textContent = `Operation failed: ${error.message}`;
        sequence.trace("UI / JS", "Lab state", `Web Crypto operation failed: ${error.message}`, "error");
      } finally {
        state.busy = false;
        updateButtons();
      }
    }

    function setNode(name, text, ready) {
      const node = lab.querySelector(`[data-pki-node="${name}"]`);
      const labels = {
        root: lab.querySelector("[data-pki-root-node]"),
        certificate: lab.querySelector("[data-pki-certificate-node]"),
        message: lab.querySelector("[data-pki-message-node]"),
      };
      node.dataset.state = ready ? "ready" : "";
      labels[name].textContent = text;
    }

    function signBytes(privateKey, bytes) {
      return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, bytes);
    }

    async function fingerprint(publicJwk) {
      sequence.trace("UI / JS", "Web Crypto API", "subtle.digest(SHA-256, UTF-8(JSON(public JWK)))");
      const digest = await subtle.digest("SHA-256", encoder.encode(JSON.stringify(publicJwk)));
      const truncated = [...new Uint8Array(digest)].slice(0, 8).map((byte) => byte.toString(16).padStart(2, "0")).join("");
      sequence.trace("Web Crypto API", "UI / JS", `Return first 8 SHA-256 bytes as display fingerprint (${truncated})`);
      return truncated;
    }

    function setCheck(name, valid) {
      const output = lab.querySelector(`[data-pki-${name}-check]`);
      output.textContent = valid ? "VALID" : "INVALID";
      output.dataset.state = valid ? "valid" : "invalid";
    }

    async function verifyAll() {
      const algorithm = { name: "ECDSA", hash: "SHA-256" };
      sequence.trace("JS verifier", "Lab state", "Read root public key pinned by this demo as trust anchor");
      sequence.trace("JS verifier", "Web Crypto API", "subtle.verify(ECDSA/SHA-256, root publicKey, signature, UTF-8(JSON(root body)))");
      const rootSignatureValid = await subtle.verify(
        algorithm,
        state.root.keyPair.publicKey,
        state.root.signature,
        encoder.encode(JSON.stringify(state.root.body)),
      );
      sequence.trace("Web Crypto API", "JS verifier", `Root signature result: ${rootSignatureValid}`, rootSignatureValid ? "success" : "error");
      sequence.trace("JS verifier", "Web Crypto API", "subtle.verify(ECDSA/SHA-256, root publicKey, certificate signature, UTF-8(JSON(cert body)))");
      const certificateSignatureValid = await subtle.verify(
        algorithm,
        state.root.keyPair.publicKey,
        state.identity.signature,
        encoder.encode(JSON.stringify(state.identity.body)),
      );
      sequence.trace("Web Crypto API", "JS verifier", `Certificate signature result: ${certificateSignatureValid}`, certificateSignatureValid ? "success" : "error");
      const now = Date.now();
      const certificateValid = certificateSignatureValid
        && state.identity.body.issuer === state.root.body.subject
        && now >= state.identity.body.notBefore
        && now <= state.identity.body.notAfter;
      sequence.trace("JS verifier", "JS verifier", `Check issuer === root.subject and now within validity: ${certificateValid}`, certificateValid ? "success" : "error");
      sequence.trace("JS verifier", "Web Crypto API", "subtle.verify(ECDSA/SHA-256, identity publicKey, signature, UTF-8(message))");
      const messageValid = await subtle.verify(
        algorithm,
        state.identity.keyPair.publicKey,
        state.messageSignature,
        encoder.encode(messageInput.value),
      );
      sequence.trace("Web Crypto API", "JS verifier", `Message signature result: ${messageValid}`, messageValid ? "success" : "error");

      checks.hidden = false;
      setCheck("root", rootSignatureValid);
      setCheck("certificate", certificateValid);
      setCheck("message", messageValid);
      messageStatus.textContent = rootSignatureValid && certificateValid && messageValid
        ? "Trust chain and message signature are valid."
        : "At least one check failed. The message may have changed since it was signed.";
    }

    rootButton.addEventListener("click", () => runAction(async () => {
      sequence.reset("Generating and pinning a demo root locally.");
      sequence.trace("UI / JS", "Web Crypto API", "subtle.generateKey(ECDSA/P-256, extractable=false, usages=[sign,verify])");
      state.root = null;
      state.identity = null;
      state.messageSignature = null;
      checks.hidden = true;
      setNode("root", "Creating…", false);
      setNode("certificate", "Waiting for root", false);
      setNode("message", "Waiting for certificate", false);
      issueButton.disabled = true;
      signButton.disabled = true;
      verifyButton.disabled = true;
      tamperButton.disabled = true;

      const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      sequence.trace("Web Crypto API", "UI / JS", "Return CryptoKeyPair; private key is non-extractable");
      sequence.trace("UI / JS", "Web Crypto API", "subtle.exportKey('jwk', root publicKey)");
      const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);
      const now = Date.now();
      const body = {
        subject: "Rafael Demo Root CA",
        issuer: "Rafael Demo Root CA",
        serial: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
        notBefore: now - 60_000,
        notAfter: now + 86_400_000,
        publicKey: publicJwk,
      };
      sequence.trace("UI / JS", "Web Crypto API", "subtle.sign(ECDSA/SHA-256, root privateKey, UTF-8(JSON(root body)))");
      const signature = await signBytes(keyPair.privateKey, encoder.encode(JSON.stringify(body)));
      const keyFingerprint = await fingerprint(publicJwk);
      state.root = { keyPair, body, signature };
      sequence.trace("UI / JS", "Lab state", "Store root CryptoKeyPair as explicitly trusted demo anchor; self-signature alone is not trust");
      rootStatus.textContent = `Demo CA ready. Public-key fingerprint SHA-256: ${keyFingerprint}.`;
      certificateStatus.textContent = "The CA can now issue an identity certificate.";
      messageStatus.textContent = "Issue a certificate first.";
      setNode("root", "Trusted for this lab", true);
      setNode("certificate", "Not issued", false);
      setNode("message", "Not signed", false);
    }, rootStatus));

    issueButton.addEventListener("click", () => runAction(async () => {
      sequence.trace("UI / JS", "Web Crypto API", "subtle.generateKey(ECDSA/P-256, extractable=false, usages=[sign,verify])");
      const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      sequence.trace("Web Crypto API", "UI / JS", "Return identity CryptoKeyPair");
      sequence.trace("UI / JS", "Web Crypto API", "subtle.exportKey('jwk', identity publicKey)");
      const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);
      const now = Date.now();
      const body = {
        subject: "Demo User",
        issuer: state.root.body.subject,
        serial: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
        notBefore: now - 60_000,
        notAfter: now + 3_600_000,
        publicKey: publicJwk,
      };
      sequence.trace("UI / JS", "Web Crypto API", "subtle.sign(ECDSA/SHA-256, pinned root privateKey, UTF-8(JSON(certificate body)))");
      const signature = await signBytes(state.root.keyPair.privateKey, encoder.encode(JSON.stringify(body)));
      const keyFingerprint = await fingerprint(publicJwk);
      state.identity = { keyPair, body, signature };
      sequence.trace("UI / JS", "Lab state", "Store certificate body, signature and identity CryptoKeyPair");
      state.messageSignature = null;
      checks.hidden = true;
      certificateStatus.textContent = `Demo User certificate issued. Key fingerprint SHA-256: ${keyFingerprint}.`;
      messageStatus.textContent = "Certificate issued. Enter a message and sign it.";
      setNode("certificate", "Signed by demo CA", true);
      setNode("message", "Not signed", false);
    }, certificateStatus));

    signButton.addEventListener("click", () => runAction(async () => {
      if (!messageInput.value.trim()) throw new Error("Enter a message before signing.");
      sequence.trace("UI / JS", "Web Crypto API", "subtle.sign(ECDSA/SHA-256, identity privateKey, UTF-8(message))");
      state.messageSignature = await signBytes(state.identity.keyPair.privateKey, encoder.encode(messageInput.value));
      state.signedMessage = messageInput.value;
      sequence.trace("Web Crypto API", "Lab state", "Store signature bytes and exact signed message in JS memory");
      messageStatus.textContent = "Message signed with the identity private key. Verify it, or alter the text to see verification fail.";
      checks.hidden = true;
      setNode("message", "Signed with private key", true);
    }, messageStatus));

    verifyButton.addEventListener("click", () => runAction(verifyAll, messageStatus));

    tamperButton.addEventListener("click", () => runAction(async () => {
      if (messageInput.value === state.signedMessage) messageInput.value += " [altered]";
      else messageInput.value = state.signedMessage;
      await verifyAll();
    }, messageStatus));

    messageInput.addEventListener("input", () => {
      if (state.messageSignature && messageInput.value !== state.signedMessage) {
        messageStatus.textContent = "Message changed since signing. Verify it to check the original signature against this text.";
      }
    });

    updateButtons();
  }

  function initContractDemo(simulator, sequence) {
    if (!simulator) return;

    const stockOutput = simulator.querySelector("[data-contract-stock]");
    const balanceOutput = simulator.querySelector("[data-contract-balance]");
    const status = simulator.querySelector("[data-contract-status]");
    const eventLog = simulator.querySelector("[data-contract-events]");
    const buyButton = simulator.querySelector("[data-contract-buy]");
    const paymentInput = simulator.querySelector("[data-contract-payment]");
    let stock = 3;
    let balanceWei = 0n;
    let purchases = 0;
    const priceWei = 10_000_000_000_000_000n;

    function updateState() {
      stockOutput.textContent = String(stock);
      balanceOutput.textContent = `${(Number(balanceWei) / 1e18).toFixed(2)} ETH`;
    }

    function addLog(message, stateName) {
      const item = document.createElement("li");
      item.textContent = `${new Date().toLocaleTimeString()} · ${message}`;
      item.dataset.state = stateName;
      eventLog.prepend(item);
    }

    buyButton.addEventListener("click", () => {
      const paymentWei = BigInt(paymentInput.value);
      const sentAmount = paymentInput.selectedOptions[0].dataset.display;
      sequence.trace("Demo UI", "JS contract model", `Read selected value; BigInt(option.value) = ${paymentWei} wei`);
      if (stock <= 0) {
        sequence.trace("JS contract model", "Local state", "Evaluate stock <= 0: true; take sold-out branch", "error");
        status.textContent = 'Transaction reverted: "Sold out". Contract state is unchanged.';
        status.dataset.state = "error";
        addLog("Reverted · Sold out · state unchanged", "error");
        sequence.trace("JS contract model", "Demo UI", "Return before local state mutation; state unchanged", "error");
        return;
      }
      sequence.trace("JS contract model", "Local state", "Evaluate stock <= 0: false; continue to price guard");

      if (paymentWei !== priceWei) {
        sequence.trace("JS contract model", "Local state", `Evaluate paymentWei !== priceWei: true (${paymentWei} != ${priceWei} wei)`, "error");
        status.textContent = `Transaction reverted: wrong amount. Sent ${sentAmount}; expected 0.01 ETH. Contract state is unchanged.`;
        status.dataset.state = "error";
        addLog(`Reverted · Wrong amount (${sentAmount}) · state unchanged`, "error");
        sequence.trace("JS contract model", "Demo UI", "Return before local state mutation; state unchanged", "error");
        return;
      }
      sequence.trace("JS contract model", "Local state", "Evaluate paymentWei !== priceWei: false; continue");

      stock -= 1;
      balanceWei += priceWei;
      purchases += 1;
      updateState();
      sequence.trace("JS contract model", "Local state", `JS mutation: stock=${stock}; balanceWei += ${priceWei}`);
      status.textContent = "Purchase complete. Stock decreased and the contract balance increased.";
      status.dataset.state = "success";
      addLog(`Purchased · 0.01 ETH · transaction ${purchases}`, "success");
      sequence.trace("JS contract model", "Event log", `Append local UI log entry for Purchased(value=${priceWei} wei); no EVM log emitted`);
    });

    simulator.querySelector("[data-contract-reset]").addEventListener("click", () => {
      stock = 3;
      balanceWei = 0n;
      purchases = 0;
      eventLog.replaceChildren();
      updateState();
      status.textContent = "Three items are in stock. Try a purchase.";
      delete status.dataset.state;
      sequence.reset("Submit a transaction to trace its execution.");
    });
  }

  function initLoginLab(lab, sequence) {
    if (!lab) return;

    const form = lab.querySelector("[data-login-form]");
    const username = lab.querySelector("[data-login-username]");
    const password = lab.querySelector("[data-login-password]");
    const lockoutToggle = lab.querySelector("[data-login-lockout]");
    const mfaToggle = lab.querySelector("[data-login-mfa]");
    const primaryFields = lab.querySelector("[data-login-primary-fields]");
    const mfaField = lab.querySelector("[data-login-mfa-field]");
    const mfaContext = lab.querySelector("[data-login-mfa-context]");
    const mfaCode = lab.querySelector("[data-login-code]");
    const submitButton = lab.querySelector("[data-login-submit]");
    const status = lab.querySelector("[data-login-status]");
    const attemptOutput = lab.querySelector("[data-login-attempts]");
    const failureOutput = lab.querySelector("[data-login-failures]");
    const stateOutput = lab.querySelector("[data-login-state]");
    const eventLog = lab.querySelector("[data-login-events]");
    const demoUsername = "demo-user";
    const demoPassword = "riverstone";
    const demoCode = "042731";
    const attackGuesses = ["welcome1", "password1", "admin123", demoPassword];
    const state = { attempts: 0, failures: 0, locked: false, authenticated: false, challengePending: false, label: "Ready" };

    function updateSummary() {
      attemptOutput.textContent = String(state.attempts);
      failureOutput.textContent = String(state.failures);
      stateOutput.textContent = state.label;
      mfaField.hidden = !state.challengePending;
      primaryFields.hidden = state.challengePending;
      submitButton.textContent = state.challengePending ? "Verify MFA code" : state.authenticated ? "Signed in" : "Sign in";
      submitButton.disabled = state.locked || state.authenticated;
    }

    function addEvent(message, result) {
      const item = document.createElement("li");
      item.textContent = `Attempt ${state.attempts} · ${message}`;
      item.dataset.state = result;
      eventLog.prepend(item);
    }

    function recordFailure(message) {
      state.failures += 1;
      state.label = "Rejected";
      addEvent(message, "failure");
      sequence.trace("Login simulator", "Local state", `failures += 1 → ${state.failures}`);
      const lockoutReached = lockoutToggle.checked && state.failures >= 3;
      sequence.trace("Login simulator", "Local state", `Evaluate lockoutToggle.checked && failures >= 3 → ${lockoutReached}`);
      if (lockoutToggle.checked && state.failures >= 3) {
        state.locked = true;
        state.challengePending = false;
        state.label = "Locked";
        status.textContent = "Three failures reached. The demo account is locked until you reset the lab.";
        addEvent("Temporary lockout applied", "blocked");
        sequence.trace("Login simulator", "Local state", "Set locked=true; reject subsequent attempts", "error");
      } else {
        status.textContent = "Sign-in failed. Check the demo credentials and try again.";
      }
      status.dataset.state = "error";
      updateSummary();
    }

    function acceptPassword(candidate, attackIndex = 0) {
      state.attempts += 1;
      sequence.trace(
        "UI / guess loop",
        "Login simulator",
        attackIndex ? `Call acceptPassword(candidate, fixed guess ${attackIndex})` : "Call acceptPassword(candidate)",
      );
      if (username.value !== demoUsername || candidate !== demoPassword) {
        sequence.trace("Login simulator", "Login simulator", "Evaluate username !== demoUsername || candidate !== demoPassword → true (plain string comparison)", "error");
        recordFailure("Credentials rejected");
        return "failed";
      }
      sequence.trace("Login simulator", "Login simulator", "Evaluate username !== demoUsername || candidate !== demoPassword → false (plain string comparison)");

      if (mfaToggle.checked) {
        state.challengePending = true;
        state.label = "MFA required";
        mfaContext.textContent = attackIndex
          ? `Password accepted on guess ${attackIndex}. Enter the code below to complete sign-in.`
          : `Password accepted for ${demoUsername}. Enter the code below to complete sign-in.`;
        status.textContent = "Step 1 of 2 passed. Complete the MFA challenge below.";
        status.dataset.state = "challenge";
        addEvent("Password accepted · second factor required", "challenge");
        sequence.trace("Login simulator", "Local state", "Set challengePending=true; authenticated remains false", "challenge");
        sequence.trace("Login simulator", "MFA input", "Render second-factor challenge");
        updateSummary();
        mfaCode.focus();
        return "challenge";
      }

      state.authenticated = true;
      state.label = "Authenticated";
      status.textContent = attackIndex
        ? `Demo attack authenticated on guess ${attackIndex}. Reset the lab to try a defense.`
        : "Signed in to the fictional demo account.";
      status.dataset.state = "success";
      addEvent("Demo session created", "success");
      sequence.trace("Login simulator", "Local state", "Set authenticated=true; no server session or cookie exists");
      updateSummary();
      return "authenticated";
    }

    function runPasswordAttempt(candidate, attackIndex = 0) {
      if (state.locked || state.authenticated) return "stopped";
      return acceptPassword(candidate, attackIndex);
    }

    function resetLab(message = "Protection settings changed. Lab reset.") {
      state.attempts = 0;
      state.failures = 0;
      state.locked = false;
      state.authenticated = false;
      state.challengePending = false;
      state.label = "Ready";
      username.value = demoUsername;
      password.value = "";
      mfaCode.value = "";
      eventLog.replaceChildren();
      status.textContent = message;
      delete status.dataset.state;
      sequence.reset("Sign in or run the fixed attack to trace the login flow.");
      updateSummary();
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (state.locked) {
        status.textContent = "Account locked. Reset the lab before trying again.";
        return;
      }
      if (state.authenticated) {
        status.textContent = "Demo session already authenticated. Reset to start again.";
        return;
      }
      if (state.challengePending) {
        state.attempts += 1;
        sequence.trace("MFA input", "Login simulator", "Submit code; increment attempts counter");
        const codeMatches = mfaCode.value === demoCode;
        sequence.trace("Login simulator", "Login simulator", `Strict compare code === demoCode → ${codeMatches}`, codeMatches ? "success" : "error");
        if (codeMatches) {
          state.authenticated = true;
          state.challengePending = false;
          state.label = "Authenticated";
          status.textContent = "MFA accepted. Signed in to the fictional demo account.";
          status.dataset.state = "success";
          addEvent("Second factor accepted · demo session created", "success");
          sequence.trace("Login simulator", "Local state", "Set challengePending=false and authenticated=true");
          updateSummary();
        } else {
          recordFailure("Second factor rejected");
        }
        return;
      }
      runPasswordAttempt(password.value);
    });

    lab.querySelector("[data-login-fill]").addEventListener("click", () => {
      username.value = demoUsername;
      password.value = demoPassword;
      status.textContent = "Demo credentials filled. Submit the form to sign in.";
      delete status.dataset.state;
    });

    lab.querySelector("[data-login-attack]").addEventListener("click", () => {
      if (state.locked || state.authenticated) {
        status.textContent = "Reset the lab before running the fixed attack again.";
        sequence.trace("UI / guess loop", "Login simulator", "Stop: reset required before another run", "error");
        return;
      }
      sequence.reset("Running the fixed offline guess sequence.");
      username.value = demoUsername;
      for (let index = 0; index < attackGuesses.length; index += 1) {
        const outcome = runPasswordAttempt(attackGuesses[index], index + 1);
        if (outcome !== "failed") break;
      }
    });

    lab.querySelector("[data-login-reset]").addEventListener("click", () => resetLab("Lab reset. Choose protections and run the demo."));
    lockoutToggle.addEventListener("change", () => resetLab());
    mfaToggle.addEventListener("change", () => resetLab());
    updateSummary();
  }
})();