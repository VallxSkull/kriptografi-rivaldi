<?php
// ssl-generator.php — SSL Certificate Generator
// Membuat CSR, Key Pair RSA, dan Self-Signed Certificate (X.509)

// ============================================================
// HELPER: Temukan openssl.cnf (Windows/Laragon/XAMPP)
// ============================================================
function getOpensslConfig(): array {
    $config = [
        'digest_alg'       => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    $phpDir = defined('PHP_BINARY') ? str_replace('\\', '/', dirname(PHP_BINARY)) : '';
    $candidates = [
        $phpDir . '/extras/ssl/openssl.cnf',
        $phpDir . '/../extras/ssl/openssl.cnf',
        'C:/xampp/php/extras/ssl/openssl.cnf',
    ];
    foreach ((array) glob('C:/laragon/bin/php/*/extras/ssl/openssl.cnf') as $p) $candidates[] = $p;
    foreach ((array) glob('C:/wamp64/bin/php/*/extras/ssl/openssl.cnf')  as $p) $candidates[] = $p;
    if (getenv('OPENSSL_CONF')) $candidates[] = getenv('OPENSSL_CONF');
    foreach ($candidates as $path) {
        $path = str_replace('\\', '/', (string)$path);
        if ($path !== '' && file_exists($path)) { $config['config'] = $path; break; }
    }
    return $config;
}

// ============================================================
// PROSES FORM POST
// ============================================================
$result       = null;
$error        = null;
$form_data    = [];
$gen_log      = [];  // Log langkah proses untuk terminal

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Ambil dan sanitasi input
    $country  = strtoupper(trim($_POST['country']      ?? 'ID'));
    $state    = trim($_POST['state']       ?? '');
    $locality = trim($_POST['locality']    ?? '');
    $org      = trim($_POST['org']         ?? '');
    $cn       = trim($_POST['cn']          ?? '');

    $form_data = compact('country', 'state', 'locality', 'org', 'cn');

    // Validasi
    if (strlen($country) !== 2)       $error = 'Kode negara harus tepat 2 huruf (contoh: ID).';
    elseif (empty($state))            $error = 'Provinsi tidak boleh kosong.';
    elseif (empty($locality))         $error = 'Kota tidak boleh kosong.';
    elseif (empty($org))              $error = 'Nama organisasi tidak boleh kosong.';
    elseif (empty($cn))               $error = 'Common Name (domain) tidak boleh kosong.';
    else {
        $cfg = getOpensslConfig();
        $gen_log[] = ['ok',  'Memuat konfigurasi OpenSSL ...'];
        if (isset($cfg['config'])) {
            $gen_log[] = ['ok', 'Config: ' . $cfg['config']];
        }

        // STEP 1 — Generate RSA Key Pair
        $gen_log[] = ['run', 'Membangkitkan RSA 2048-bit key pair ...'];
        $pkey = openssl_pkey_new($cfg);

        if ($pkey === false) {
            $errs = [];
            while ($m = openssl_error_string()) $errs[] = $m;
            $error = 'openssl_pkey_new() gagal: ' . (implode(' | ', $errs) ?: 'Periksa konfigurasi OpenSSL.');
            $gen_log[] = ['err', 'Key generation GAGAL — ' . ($errs[0] ?? 'unknown error')];
        } else {
            $gen_log[] = ['ok', 'RSA 2048-bit key pair berhasil dibuat.'];

            // Export private key
            openssl_pkey_export($pkey, $private_key_pem, null, $cfg);
            $kd = openssl_pkey_get_details($pkey);
            $gen_log[] = ['ok', 'Private key berhasil diekspor (' . strlen($private_key_pem) . ' bytes).'];

            // STEP 2 — Susun DN (Distinguished Name)
            $dn = [
                'countryName'            => $country,
                'stateOrProvinceName'    => $state,
                'localityName'           => $locality,
                'organizationName'       => $org,
                'commonName'             => $cn,
            ];
            $gen_log[] = ['run', 'Menyusun DN (Distinguished Name) ...'];
            $gen_log[] = ['ok',  'CN=' . $cn . ', O=' . $org . ', L=' . $locality . ', ST=' . $state . ', C=' . $country];

            // STEP 3 — Buat CSR
            $gen_log[] = ['run', 'Membuat CSR (Certificate Signing Request) ...'];
            $csr = openssl_csr_new($dn, $pkey, $cfg);

            if ($csr === false) {
                $error = 'openssl_csr_new() gagal.';
                $gen_log[] = ['err', 'CSR generation GAGAL.'];
            } else {
                $gen_log[] = ['ok', 'CSR berhasil dibuat.'];

                // STEP 4 — Self-Sign CSR → Certificate (.crt), valid 365 hari
                $gen_log[] = ['run', 'Menandatangani CSR (self-signed, 365 hari) ...'];
                $cert = openssl_csr_sign($csr, null, $pkey, 365, $cfg);

                if ($cert === false) {
                    $error = 'openssl_csr_sign() gagal.';
                    $gen_log[] = ['err', 'Certificate signing GAGAL.'];
                } else {
                    $gen_log[] = ['ok', 'Certificate (X.509) berhasil ditandatangani.'];

                    // Export ke format PEM
                    openssl_x509_export($cert, $cert_pem);
                    openssl_csr_export($csr, $csr_pem);

                    // Ambil info sertifikat
                    $cert_info = openssl_x509_parse($cert);
                    $valid_from = date('Y-m-d H:i:s', $cert_info['validFrom_time_t'] ?? time());
                    $valid_to   = date('Y-m-d H:i:s', $cert_info['validTo_time_t']   ?? time() + 365*86400);
                    $serial     = $cert_info['serialNumber'] ?? '—';
                    $fingerprint = openssl_x509_fingerprint($cert, 'sha256');

                    $gen_log[] = ['ok',  'Sertifikat valid: ' . $valid_from . ' s/d ' . $valid_to];
                    $gen_log[] = ['ok',  'SHA-256 Fingerprint: ' . strtoupper(chunk_split($fingerprint, 2, ':'))];
                    $gen_log[] = ['done','✅ SSL Certificate berhasil digenerate!'];

                    $result = [
                        'private_key' => $private_key_pem,
                        'csr'         => $csr_pem,
                        'cert'        => $cert_pem,
                        'valid_from'  => $valid_from,
                        'valid_to'    => $valid_to,
                        'serial'      => $serial,
                        'fingerprint' => strtoupper(chunk_split($fingerprint, 2, ':')),
                        'cn'          => $cn,
                        'org'         => $org,
                        'key_bits'    => $kd['bits'] ?? 2048,
                    ];
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSL Generator v1.0 - KriptoVall</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
  <style>
    /* ══════════════════════════════════════════
       SSL GENERATOR — Custom Styles
    ══════════════════════════════════════════ */

    /* Page layout */
    .ssl-page {
      min-height: 100vh;
      background: #f0f2f5;
    }

    /* Hero header */
    .ssl-hero {
      text-align: center;
      padding: 52px 20px 36px;
      position: relative;
    }
    .ssl-hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(47,160,132,0.1);
      border: 1px solid rgba(47,160,132,0.3);
      color: #1F6F5F;
      padding: 6px 18px;
      border-radius: 100px;
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 18px;
    }
    .ssl-hero h1 {
      font-family: 'Syne', sans-serif;
      font-size: clamp(2rem, 5vw, 3rem);
      font-weight: 800;
      color: #111;
      letter-spacing: -1px;
      line-height: 1.1;
    }
    .ssl-hero h1 span { color: #2FA084; }
    .ssl-hero p {
      font-size: 0.95rem;
      color: #666;
      margin-top: 10px;
    }

    /* Main grid */
    .ssl-grid {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 24px;
      max-width: 1160px;
      margin: 0 auto;
      padding: 0 24px;
      align-items: start;
    }

    /* ── FORM PANEL ── */
    .form-panel {
      background: #ffffff;
      border-radius: 20px;
      padding: 32px;
      box-shadow: 0 4px 32px rgba(0,0,0,0.08);
      border: 1px solid rgba(0,0,0,0.06);
    }
    .form-panel-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 26px;
    }
    .form-panel-icon {
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, #6FCF97, #2FA084);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1rem;
      flex-shrink: 0;
    }
    .form-panel-header h2 {
      font-family: 'Syne', sans-serif;
      font-size: 1.1rem;
      font-weight: 700;
      color: #111;
    }

    /* Form fields */
    .ssl-field {
      margin-bottom: 18px;
    }
    .ssl-field label {
      display: block;
      font-size: 0.82rem;
      font-weight: 600;
      color: #444;
      margin-bottom: 7px;
      letter-spacing: 0.2px;
    }
    .ssl-field label span {
      color: #999;
      font-weight: 400;
    }
    .ssl-field input {
      width: 100%;
      padding: 11px 14px;
      border: 1.5px solid #e5e7eb;
      border-radius: 10px;
      font-family: 'Space Grotesk', sans-serif;
      font-size: 0.9rem;
      color: #111;
      background: #fafafa;
      transition: all 0.2s;
      outline: none;
      box-sizing: border-box;
    }
    .ssl-field input:focus {
      border-color: #2FA084;
      background: #fff;
      box-shadow: 0 0 0 3px rgba(47,160,132,0.1);
    }
    .ssl-field input::placeholder { color: #bbb; }

    /* Country row */
    .field-row {
      display: grid;
      grid-template-columns: 100px 1fr;
      gap: 12px;
    }

    /* Submit button */
    .btn-generate {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #2FA084, #1F6F5F);
      color: white;
      border: none;
      border-radius: 12px;
      font-family: 'Syne', sans-serif;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.25s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 8px;
      letter-spacing: 0.3px;
      box-shadow: 0 4px 16px rgba(47,160,132,0.3);
    }
    .btn-generate:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 28px rgba(47,160,132,0.4);
    }
    .btn-generate:active { transform: translateY(0); }

    /* Error banner */
    .ssl-error {
      background: #fff5f5;
      border: 1.5px solid #fca5a5;
      border-radius: 10px;
      padding: 12px 16px;
      color: #dc2626;
      font-size: 0.85rem;
      margin-bottom: 18px;
      display: flex;
      gap: 8px;
      align-items: flex-start;
    }

    /* ── TERMINAL PANEL ── */
    .terminal-panel {
      background: #0d1117;
      border-radius: 20px;
      overflow: hidden;
      box-shadow: 0 8px 40px rgba(0,0,0,0.25);
      border: 1px solid rgba(255,255,255,0.06);
      display: flex;
      flex-direction: column;
      min-height: 520px;
    }

    /* Terminal titlebar */
    .term-bar {
      background: #161b22;
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      flex-shrink: 0;
    }
    .term-dots {
      display: flex;
      gap: 7px;
    }
    .term-dot {
      width: 13px;
      height: 13px;
      border-radius: 50%;
    }
    .dot-red    { background: #ff5f57; }
    .dot-yellow { background: #febc2e; }
    .dot-green  { background: #28c840; }
    .term-title {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: #7a8b9a;
      margin-left: auto;
    }

    /* Terminal body */
    .term-body {
      flex: 1;
      padding: 22px 24px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      line-height: 1.7;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }

    /* Idle state */
    .term-idle {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #2a3a4a;
      gap: 14px;
    }
    .term-idle-icon {
      font-size: 3rem;
      opacity: 0.4;
    }
    .term-idle p {
      font-size: 0.82rem;
      color: #3a4a5a;
    }

    /* Log lines */
    .log-line {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      margin-bottom: 4px;
    }
    .log-prompt { color: #2FA084; flex-shrink: 0; }
    .log-run    { color: #6FCF97; }
    .log-ok     { color: #a8e6c5; }
    .log-err    { color: #ff6b6b; }
    .log-done   { color: #ffd700; font-weight: 700; }
    .log-ts {
      color: #3a4a5a;
      font-size: 0.72rem;
      flex-shrink: 0;
      margin-top: 2px;
    }

    /* Divider line in terminal */
    .term-divider {
      border: none;
      border-top: 1px solid rgba(255,255,255,0.06);
      margin: 16px 0;
    }

    /* Section title in terminal */
    .term-section {
      color: #4a7a6a;
      font-size: 0.72rem;
      letter-spacing: 1px;
      text-transform: uppercase;
      margin: 14px 0 8px;
    }

    /* ── OUTPUT TABS ── */
    .output-tabs {
      display: flex;
      gap: 2px;
      background: #161b22;
      padding: 10px 16px 0;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .tab-btn {
      padding: 8px 16px;
      border: none;
      background: transparent;
      color: #4a6a5a;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      cursor: pointer;
      border-radius: 6px 6px 0 0;
      transition: all 0.2s;
      font-weight: 500;
    }
    .tab-btn:hover { color: #aaa; background: rgba(255,255,255,0.04); }
    .tab-btn.active {
      background: #0d1117;
      color: #6FCF97;
      border-top: 1.5px solid #2FA084;
      border-left: 1px solid rgba(255,255,255,0.06);
      border-right: 1px solid rgba(255,255,255,0.06);
    }

    /* Tab content */
    .tab-content { display: none; }
    .tab-content.active { display: flex; flex-direction: column; flex: 1; }

    /* PEM textarea */
    .pem-area {
      flex: 1;
      padding: 20px 22px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.76rem;
      background: transparent;
      border: none;
      color: #a8e6c5;
      resize: none;
      line-height: 1.7;
      outline: none;
      min-height: 320px;
    }
    .pem-area.pem-key   { color: #88bbff; }
    .pem-area.pem-cert  { color: #a8e6c5; }
    .pem-area.pem-csr   { color: #ffcc88; }

    /* Copy button in tab */
    .tab-copy-row {
      padding: 10px 18px 14px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      border-top: 1px solid rgba(255,255,255,0.05);
    }
    .btn-copy-pem {
      padding: 7px 16px;
      background: rgba(47,160,132,0.15);
      border: 1px solid rgba(47,160,132,0.3);
      color: #6FCF97;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy-pem:hover { background: rgba(47,160,132,0.28); }

    /* ── CERT INFO CARD ── */
    .cert-info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      padding: 16px 20px;
    }
    .cert-info-item {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 8px;
      padding: 10px 14px;
    }
    .cert-info-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.68rem;
      color: #4a7a6a;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      margin-bottom: 4px;
    }
    .cert-info-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: #c0ddd0;
      font-weight: 500;
      word-break: break-all;
    }
    .cert-info-value.val-green { color: #6FCF97; }
    .cert-info-value.val-yellow { color: #ffd700; }
    .cert-info-full {
      grid-column: 1 / -1;
    }

    /* ── HOW IT WORKS (below grid) ── */
    .how-section {
      max-width: 1160px;
      margin: 32px auto 0;
      padding: 0 24px;
    }
    .how-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .how-card {
      background: #fff;
      border-radius: 16px;
      padding: 22px;
      border: 1px solid rgba(0,0,0,0.06);
      box-shadow: 0 2px 12px rgba(0,0,0,0.05);
      text-align: center;
    }
    .how-num {
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, #6FCF97, #2FA084);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Syne', sans-serif;
      font-weight: 800;
      font-size: 0.9rem;
      color: white;
      margin: 0 auto 12px;
    }
    .how-title {
      font-family: 'Syne', sans-serif;
      font-weight: 700;
      font-size: 0.9rem;
      color: #111;
      margin-bottom: 6px;
    }
    .how-desc {
      font-size: 0.8rem;
      color: #888;
      line-height: 1.6;
    }

    /* Footer */
    .ssl-footer {
      text-align: center;
      padding: 32px 20px 0;
      color: #999;
      font-size: 0.82rem;
    }
    .ssl-footer a { color: #2FA084; text-decoration: none; }

    /* Responsive */
    @media (max-width: 900px) {
      .ssl-grid { grid-template-columns: 1fr; }
      .terminal-panel { min-height: 400px; }
    }
    @media (max-width: 480px) {
      .ssl-hero { padding: 36px 16px 24px; }
      .ssl-grid { padding: 0 16px; }
      .form-panel { padding: 24px 20px; }
      .field-row { grid-template-columns: 80px 1fr; }
      .cert-info-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body class="ssl-page">
<!-- ═══ NAVBAR ═══ -->
<nav class="navbar">
  <a class="navbar-brand" href="index.php">
    <div class="brand-icon">🔐</div>
    KriptoMath
  </a>
  <ul class="navbar-nav" id="navMenu">
    <li><a href="index.php">🏠 Home</a></li>
    <li><a href="kalkulator-fpb.php">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php" class="active">🛡️ SSL Generator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()"><span></span><span></span><span></span></button>
</nav>

<!-- ═══ HERO ═══ -->
<div class="ssl-hero">
  <div class="ssl-hero-badge">🛡️ KRIPTOGRAFI ASIMETRIS</div>
  <h1>SSL Generator</h1>
  <p>Hasil Implementasi Praktikum Kriptografi Asimetris</p>
</div>

<!-- ═══ MAIN GRID ═══ -->
<div class="ssl-grid">

  <!-- ── FORM PANEL KIRI ── -->
  <div class="form-panel">

    <div class="form-panel-header">
      <div class="form-panel-icon">📋</div>
      <h2>Identitas CSR</h2>
    </div>

    <?php if ($error && !str_contains($error, 'openssl_pkey_new')): ?>
    <div class="ssl-error">⚠️ <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST" action="" id="sslForm">

      <!-- Country + State row -->
      <div class="field-row" style="margin-bottom:18px;">
        <div class="ssl-field" style="margin-bottom:0;">
          <label>Negara (ID)</label>
          <input type="text" name="country" maxlength="2"
            value="<?= htmlspecialchars($form_data['country'] ?? 'ID') ?>"
            placeholder="ID" style="text-transform:uppercase;">
        </div>
        <div class="ssl-field" style="margin-bottom:0;">
          <label>Provinsi</label>
          <input type="text" name="state"
            value="<?= htmlspecialchars($form_data['state'] ?? '') ?>"
            placeholder="Misal: Kalimantan Barat">
        </div>
      </div>

      <div class="ssl-field">
        <label>Kota / Locality</label>
        <input type="text" name="locality"
          value="<?= htmlspecialchars($form_data['locality'] ?? '') ?>"
          placeholder="Misal: Pontianak">
      </div>

      <div class="ssl-field">
        <label>Organisasi</label>
        <input type="text" name="org"
          value="<?= htmlspecialchars($form_data['org'] ?? '') ?>"
          placeholder="Misal: Universitas Muhammadiyah Pontianak">
      </div>

      <div class="ssl-field">
        <label>Common Name (Domain) <span>— nama domain/server</span></label>
        <input type="text" name="cn"
          value="<?= htmlspecialchars($form_data['cn'] ?? '') ?>"
          placeholder="Misal: KriptoVall.com">
      </div>

      <button type="submit" class="btn-generate" id="btnGenerate">
        <span id="btnIcon">🔐</span>
        <span id="btnText">Generate SSL</span>
      </button>

    </form>

    <?php if ($result): ?>
    <!-- Info ringkas di bawah form setelah generate -->
    <div style="margin-top:20px;padding:16px;background:#f0faf5;border:1.5px solid #6FCF97;border-radius:12px;">
      <div style="font-size:0.78rem;font-weight:700;color:#1F6F5F;margin-bottom:10px;">✅ Sertifikat Berhasil Digenerate</div>
      <div style="font-size:0.78rem;color:#2d4a40;line-height:1.9;">
        <div><strong>CN:</strong> <?= htmlspecialchars($result['cn']) ?></div>
        <div><strong>Org:</strong> <?= htmlspecialchars($result['org']) ?></div>
        <div><strong>Valid:</strong> <?= $result['valid_from'] ?></div>
        <div><strong>Expires:</strong> <?= $result['valid_to'] ?></div>
        <div><strong>Key:</strong> RSA <?= $result['key_bits'] ?>-bit</div>
      </div>
    </div>
    <?php elseif ($error && str_contains($error, 'openssl_pkey_new')): ?>
    <div style="margin-top:16px;background:#1a0f0f;border:1.5px solid #dc3545;border-radius:12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#ffaaaa;line-height:1.9;">
      <strong style="color:#ff6b6b;">❌ OpenSSL Error</strong><br>
      <?= htmlspecialchars($error) ?><br><br>
      <strong style="color:#ffd700;">Solusi:</strong><br>
      Set env var: <code>OPENSSL_CONF=C:\laragon\bin\php\phpX.X\extras\ssl\openssl.cnf</code>
    </div>
    <?php endif; ?>
  </div>

  <!-- ── TERMINAL PANEL KANAN ── -->
  <div class="terminal-panel">

    <div class="term-bar">
      <div class="term-dots">
        <div class="term-dot dot-red"></div>
        <div class="term-dot dot-yellow"></div>
        <div class="term-dot dot-green"></div>
      </div>
      <div class="term-title">X.509 Output Terminal</div>
    </div>

    <?php if (!$result && empty($gen_log)): ?>
    <!-- IDLE STATE -->
    <div class="term-body">
      <div class="term-idle">
        <div class="term-idle-icon">🔒</div>
        <p>Silakan isi form dan klik Generate</p>
      </div>
    </div>

    <?php elseif (!$result && !empty($gen_log)): ?>
    <!-- ERROR STATE — tampilkan log -->
    <div class="term-body">
      <?php foreach ($gen_log as [$type, $msg]): ?>
      <div class="log-line">
        <span class="log-prompt">$</span>
        <span class="log-<?= $type ?>"><?= htmlspecialchars($msg) ?></span>
      </div>
      <?php endforeach; ?>
    </div>

    <?php else: ?>
    <!-- SUCCESS STATE — tabs -->

    <!-- Log tab header -->
    <div class="output-tabs">
      <button class="tab-btn active" onclick="showTab('log',this)">📟 Log</button>
      <button class="tab-btn" onclick="showTab('cert',this)">📜 Certificate</button>
      <button class="tab-btn" onclick="showTab('key',this)">🔑 Private Key</button>
      <button class="tab-btn" onclick="showTab('csr',this)">📄 CSR</button>
      <button class="tab-btn" onclick="showTab('info',this)">ℹ️ Info</button>
    </div>

    <!-- TAB: LOG -->
    <div class="tab-content active" id="tab-log">
      <div class="term-body" style="padding-top:16px;">
        <?php foreach ($gen_log as [$type, $msg]): ?>
        <div class="log-line">
          <span class="log-prompt">$</span>
          <span class="log-<?= $type ?>"><?= htmlspecialchars($msg) ?></span>
        </div>
        <?php endforeach; ?>
        <div style="margin-top:16px;height:1px;background:rgba(255,255,255,0.05);"></div>
        <div style="margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#2FA084;">
          $ openssl x509 -text -noout — lihat tab Info untuk detail<br>
          $ openssl rsa -check      — Private Key valid ✓
        </div>
      </div>
    </div>

    <!-- TAB: CERTIFICATE -->
    <div class="tab-content" id="tab-cert">
      <textarea class="pem-area pem-cert" readonly id="certPem"><?= htmlspecialchars($result['cert']) ?></textarea>
      <div class="tab-copy-row">
        <button class="btn-copy-pem" onclick="copyPem('certPem',this)">📋 Copy .crt</button>
        <button class="btn-copy-pem" onclick="downloadPem('certPem','certificate.crt')">💾 Download .crt</button>
      </div>
    </div>

    <!-- TAB: PRIVATE KEY -->
    <div class="tab-content" id="tab-key">
      <div style="padding:10px 20px 0;font-family:'JetBrains Mono',monospace;font-size:0.72rem;background:rgba(255,100,100,0.06);color:#ff8888;border-bottom:1px solid rgba(255,100,100,0.1);">
        ⚠️ SIMPAN PRIVATE KEY INI DI TEMPAT YANG AMAN — JANGAN DIBAGIKAN
      </div>
      <textarea class="pem-area pem-key" readonly id="keyPem"><?= htmlspecialchars($result['private_key']) ?></textarea>
      <div class="tab-copy-row">
        <button class="btn-copy-pem" onclick="copyPem('keyPem',this)">📋 Copy Key</button>
        <button class="btn-copy-pem" onclick="downloadPem('keyPem','private.key')">💾 Download .key</button>
      </div>
    </div>

    <!-- TAB: CSR -->
    <div class="tab-content" id="tab-csr">
      <textarea class="pem-area pem-csr" readonly id="csrPem"><?= htmlspecialchars($result['csr']) ?></textarea>
      <div class="tab-copy-row">
        <button class="btn-copy-pem" onclick="copyPem('csrPem',this)">📋 Copy CSR</button>
        <button class="btn-copy-pem" onclick="downloadPem('csrPem','request.csr')">💾 Download .csr</button>
      </div>
    </div>

    <!-- TAB: INFO -->
    <div class="tab-content" id="tab-info">
      <div class="cert-info-grid">
        <div class="cert-info-item">
          <div class="cert-info-label">Common Name</div>
          <div class="cert-info-value val-green"><?= htmlspecialchars($result['cn']) ?></div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Organization</div>
          <div class="cert-info-value"><?= htmlspecialchars($result['org']) ?></div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Valid From</div>
          <div class="cert-info-value val-green"><?= $result['valid_from'] ?></div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Expires</div>
          <div class="cert-info-value val-yellow"><?= $result['valid_to'] ?></div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Key Algorithm</div>
          <div class="cert-info-value">RSA <?= $result['key_bits'] ?>-bit</div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Signature Alg</div>
          <div class="cert-info-value">SHA-256 with RSA</div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Type</div>
          <div class="cert-info-value">Self-Signed (X.509 v3)</div>
        </div>
        <div class="cert-info-item">
          <div class="cert-info-label">Validity Period</div>
          <div class="cert-info-value val-green">365 Hari</div>
        </div>
        <div class="cert-info-item cert-info-full">
          <div class="cert-info-label">SHA-256 Fingerprint</div>
          <div class="cert-info-value" style="font-size:0.7rem;color:#88aaff;">
            <?= htmlspecialchars(rtrim($result['fingerprint'], ':')) ?>
          </div>
        </div>
        <div class="cert-info-item cert-info-full">
          <div class="cert-info-label">Subject (DN)</div>
          <div class="cert-info-value" style="font-size:0.75rem;">
            C=<?= htmlspecialchars($form_data['country'] ?? '') ?>,
            ST=<?= htmlspecialchars($form_data['state'] ?? '') ?>,
            L=<?= htmlspecialchars($form_data['locality'] ?? '') ?>,
            O=<?= htmlspecialchars($form_data['org'] ?? '') ?>,
            CN=<?= htmlspecialchars($form_data['cn'] ?? '') ?>
          </div>
        </div>
      </div>
    </div>

    <?php endif; ?>
  </div><!-- end terminal-panel -->

</div><!-- end ssl-grid -->

<!-- ═══ HOW IT WORKS ═══ -->
<div class="how-section">
  <h2 style="font-family:'Syne',sans-serif;font-size:1.2rem;font-weight:700;color:#111;margin-bottom:20px;text-align:center;">⚙️ Bagaimana SSL Generator Bekerja?</h2>
  <div class="how-grid">
    <div class="how-card">
      <div class="how-num">1</div>
      <div class="how-title">Generate RSA Key Pair</div>
      <div class="how-desc">Membuat pasangan Private Key dan Public Key menggunakan RSA 2048-bit via OpenSSL</div>
    </div>
    <div class="how-card">
      <div class="how-num">2</div>
      <div class="how-title">Susun DN Identitas</div>
      <div class="how-desc">Data form dimasukkan ke Distinguished Name (Country, State, Org, Common Name)</div>
    </div>
    <div class="how-card">
      <div class="how-num">3</div>
      <div class="how-title">Buat CSR</div>
      <div class="how-desc">Certificate Signing Request dibuat dari DN + Public Key, ditandatangani Private Key</div>
    </div>
    <div class="how-card">
      <div class="how-num">4</div>
      <div class="how-title">Self-Sign → .crt</div>
      <div class="how-desc">CSR ditandatangani sendiri menggunakan Private Key, berlaku 365 hari, format X.509 v3</div>
    </div>
    <div class="how-card">
      <div class="how-num">5</div>
      <div class="how-title">Export PEM</div>
      <div class="how-desc">Private Key (.key), Certificate (.crt), dan CSR (.csr) diekspor dalam format PEM base64</div>
    </div>
  </div>
</div>

<!-- ═══ FOOTER ═══ -->
<footer class="footer">
  <div class="footer-logo">🔐</div>
  <p><strong><a href="index.php">KriptoVall</a></strong> Tugas-tugas dari Mata Kuliah Kriptografi</p>
  <p style="margin-top: 8px; font-size: 0.8rem; opacity: 0.6;">Built with PHP Native · HTML5 · CSS3 · JavaScript</p>
</footer>

<script>
function toggleNav() {
  document.getElementById('navMenu').classList.toggle('open');
}

/* Tab switching */
function showTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(function(t) {
    t.classList.remove('active');
  });
  document.querySelectorAll('.tab-btn').forEach(function(b) {
    b.classList.remove('active');
  });
  var tc = document.getElementById('tab-' + name);
  if (tc) tc.classList.add('active');
  if (btn) btn.classList.add('active');
}

/* Copy PEM to clipboard */
function copyPem(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.value.trim()).then(function() {
    var orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    setTimeout(function() { btn.textContent = orig; }, 2000);
  }).catch(function() {
    el.select();
    document.execCommand('copy');
    btn.textContent = '✅ Copied!';
    setTimeout(function() { btn.textContent = '📋 Copy'; }, 2000);
  });
}

/* Download PEM as file */
function downloadPem(id, filename) {
  var el = document.getElementById(id);
  if (!el) return;
  var blob = new Blob([el.value], { type: 'text/plain' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* Button loading state */
document.getElementById('sslForm').addEventListener('submit', function() {
  document.getElementById('btnText').textContent = 'Generating...';
  document.getElementById('btnIcon').textContent = '⏳';
});
</script>
</body>
</html>