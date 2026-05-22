<?php
// sha256-generator.php — SHA-256 Hashing Generator
// Mendukung: text hashing, file hashing, HMAC, hash comparison, integrity check

// ─────────────────────────────────────────────
// HELPER: Tampilkan binary dari hex
// ─────────────────────────────────────────────
function hex_to_binary_blocks(string $hex): array {
    $blocks = [];
    for ($i = 0; $i < strlen($hex); $i += 2) {
        $byte    = substr($hex, $i, 2);
        $decimal = hexdec($byte);
        $binary  = str_pad(decbin($decimal), 8, '0', STR_PAD_LEFT);
        $blocks[] = ['hex' => strtoupper($byte), 'dec' => $decimal, 'bin' => $binary];
    }
    return $blocks;
}

// ─────────────────────────────────────────────
// HELPER: Tampilkan bitwise difference antara dua hash
// ─────────────────────────────────────────────
function compare_hashes(string $h1, string $h2): array {
    $diff = [];
    for ($i = 0; $i < min(strlen($h1), strlen($h2)); $i++) {
        $diff[] = ($h1[$i] !== $h2[$i]);
    }
    return $diff;
}

// ─────────────────────────────────────────────
// PROCESSING
// ─────────────────────────────────────────────
$mode      = $_POST['mode'] ?? 'text';
$result    = null;
$error     = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ── MODE: Text Hash ──
    if ($mode === 'text') {
        $text     = $_POST['text']      ?? '';
        $encoding = $_POST['encoding']  ?? 'hex';

        if (trim($text) === '') {
            $error = 'Teks tidak boleh kosong.';
        } else {
            $hash_hex    = hash('sha256', $text);
            $hash_raw    = hash('sha256', $text, true);
            $hash_b64    = base64_encode($hash_raw);
            $hash_b64url = rtrim(strtr($hash_b64, '+/', '-_'), '=');
            $bit_length  = 256;

            // Perbandingan avalanche: ubah 1 karakter
            if (strlen($text) > 0) {
                $tweaked      = $text;
                $tweaked[0]   = chr(ord($tweaked[0]) ^ 1); // flip 1 bit
                $hash_tweaked = hash('sha256', $tweaked);
                $diff_bits    = compare_hashes($hash_hex, $hash_tweaked);
                $diff_count   = count(array_filter($diff_bits));
            } else {
                $hash_tweaked = null;
                $diff_bits    = [];
                $diff_count   = 0;
            }

            $result = [
                'mode'         => 'text',
                'input'        => $text,
                'hash_hex'     => $hash_hex,
                'hash_b64'     => $hash_b64,
                'hash_b64url'  => $hash_b64url,
                'hash_upper'   => strtoupper($hash_hex),
                'hash_spaced'  => implode(' ', str_split(strtoupper($hash_hex), 2)),
                'hash_tweaked' => $hash_tweaked,
                'diff_bits'    => $diff_bits,
                'diff_count'   => $diff_count,
                'blocks'       => hex_to_binary_blocks($hash_hex),
                'input_len'    => strlen($text),
                'input_bytes'  => strlen($text),
            ];
        }
    }

    // ── MODE: HMAC ──
    elseif ($mode === 'hmac') {
        $text = $_POST['hmac_text'] ?? '';
        $key  = $_POST['hmac_key']  ?? '';

        if (trim($text) === '') $error = 'Pesan tidak boleh kosong.';
        elseif (trim($key) === '') $error = 'Kunci HMAC tidak boleh kosong.';
        else {
            $hmac_hex  = hash_hmac('sha256', $text, $key);
            $hmac_raw  = hash_hmac('sha256', $text, $key, true);
            $hmac_b64  = base64_encode($hmac_raw);

            // Bandingkan HMAC dengan kunci berbeda
            $hmac_wrong_key = hash_hmac('sha256', $text, $key . 'x');
            $diff           = compare_hashes($hmac_hex, $hmac_wrong_key);
            $diff_count     = count(array_filter($diff));

            $result = [
                'mode'            => 'hmac',
                'input'           => $text,
                'key'             => $key,
                'hmac_hex'        => $hmac_hex,
                'hmac_b64'        => $hmac_b64,
                'hmac_upper'      => strtoupper($hmac_hex),
                'hmac_spaced'     => implode(' ', str_split(strtoupper($hmac_hex), 2)),
                'hmac_wrong_key'  => $hmac_wrong_key,
                'diff_bits'       => $diff,
                'diff_count'      => $diff_count,
            ];
        }
    }

    // ── MODE: Compare ──
    elseif ($mode === 'compare') {
        $text1 = $_POST['text1'] ?? '';
        $text2 = $_POST['text2'] ?? '';

        if (trim($text1) === '' || trim($text2) === '') {
            $error = 'Kedua teks tidak boleh kosong.';
        } else {
            $h1      = hash('sha256', $text1);
            $h2      = hash('sha256', $text2);
            $match   = hash_equals($h1, $h2);
            $diff    = compare_hashes($h1, $h2);
            $changed = count(array_filter($diff));

            $result = [
                'mode'    => 'compare',
                'text1'   => $text1,
                'text2'   => $text2,
                'hash1'   => $h1,
                'hash2'   => $h2,
                'match'   => $match,
                'diff'    => $diff,
                'changed' => $changed,
                'total'   => strlen($h1),
            ];
        }
    }

    // ── MODE: File Hash ──
    elseif ($mode === 'file') {
        if (!isset($_FILES['hashfile']) || $_FILES['hashfile']['error'] !== UPLOAD_ERR_OK) {
            $error = 'File tidak berhasil diupload. Periksa ukuran dan tipe file.';
        } else {
            $file     = $_FILES['hashfile'];
            $tmp_path = $file['tmp_name'];
            $filename = htmlspecialchars($file['name']);
            $filesize = $file['size'];

            $hash_hex = hash_file('sha256', $tmp_path);
            $hash_raw = hash_file('sha256', $tmp_path, true);
            $hash_b64 = base64_encode($hash_raw);

            $result = [
                'mode'      => 'file',
                'filename'  => $filename,
                'filesize'  => $filesize,
                'hash_hex'  => $hash_hex,
                'hash_b64'  => $hash_b64,
                'hash_upper'=> strtoupper($hash_hex),
                'hash_spaced'=> implode(' ', str_split(strtoupper($hash_hex), 2)),
            ];
        }
    }

    // ── MODE: Integrity Check ──
    elseif ($mode === 'integrity') {
        $text         = $_POST['int_text']     ?? '';
        $known_hash   = strtolower(trim($_POST['int_hash'] ?? ''));

        if (trim($text) === '')       $error = 'Teks/data tidak boleh kosong.';
        elseif (strlen($known_hash) !== 64 || !ctype_xdigit($known_hash)) {
            $error = 'Hash SHA-256 yang dimasukkan tidak valid (harus 64 karakter hex).';
        } else {
            $computed = hash('sha256', $text);
            $valid    = hash_equals($computed, $known_hash);
            $diff     = compare_hashes($computed, $known_hash);
            $changed  = count(array_filter($diff));

            $result = [
                'mode'     => 'integrity',
                'input'    => $text,
                'known'    => $known_hash,
                'computed' => $computed,
                'valid'    => $valid,
                'diff'     => $diff,
                'changed'  => $changed,
            ];
        }
    }
}

// ─────────────────────────────────────────────
// Beberapa contoh hash untuk halaman idle
// ─────────────────────────────────────────────
$examples = [
    ['text' => 'Hello, World!',   'hash' => hash('sha256', 'Hello, World!')],
    ['text' => 'KriptoVall 2026', 'hash' => hash('sha256', 'KriptoVall 2026')],
    ['text' => '1234567890',      'hash' => hash('sha256', '1234567890')],
];
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHA-256 Generator - KriptoVall</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
  <style>
    /* ══════════════════════════════════
       SHA-256 PAGE STYLES
    ══════════════════════════════════ */
    body { background: #f0f2f5; }

    /* ── MODE TABS ── */
    .mode-tabs {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 28px;
    }
    .mode-tab {
      padding: 9px 18px;
      border-radius: 100px;
      border: 1.5px solid var(--border);
      background: var(--white);
      font-family: 'Space Grotesk', sans-serif;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-light);
      cursor: pointer;
      transition: var(--transition);
    }
    .mode-tab:hover { border-color: var(--green-mid); color: var(--green-mid); }
    .mode-tab.active {
      background: linear-gradient(135deg, var(--green-mid), var(--green-dark));
      border-color: transparent;
      color: white;
      box-shadow: 0 4px 12px rgba(47,160,132,0.28);
    }

    /* ── HASH DISPLAY ── */
    .hash-display-wrap {
      background: #0d1117;
      border-radius: 14px;
      border: 1px solid rgba(111,207,151,0.15);
      overflow: hidden;
      margin-bottom: 16px;
    }
    .hash-display-bar {
      background: #161b22;
      padding: 10px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .hash-display-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #4a7a6a;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .hash-display-body {
      padding: 18px 20px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      color: #6FCF97;
      word-break: break-all;
      letter-spacing: 0.5px;
      line-height: 1.7;
    }
    .hash-display-body.alt { color: #88bbff; }
    .hash-display-body.warn { color: #ffd700; }

    /* ── HASH BYTE GRID ── */
    .byte-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      padding: 14px 16px;
    }
    .byte-cell {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 32px;
    }
    .byte-hex {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.68rem;
      font-weight: 700;
      width: 28px;
      height: 28px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(111,207,151,0.12);
      color: #6FCF97;
      border: 1px solid rgba(111,207,151,0.2);
      transition: background 0.15s;
    }
    .byte-hex.diff { background: rgba(255,107,107,0.15); color: #ff8888; border-color: rgba(255,107,107,0.3); }
    .byte-hex.same { background: rgba(111,207,151,0.12); color: #6FCF97; border-color: rgba(111,207,151,0.2); }
    .byte-idx {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.55rem;
      color: #3a4a3a;
      margin-top: 3px;
    }

    /* ── DIFF COMPARE ── */
    .diff-bar {
      height: 8px;
      border-radius: 100px;
      background: #161b22;
      overflow: hidden;
      margin: 8px 0;
    }
    .diff-fill {
      height: 100%;
      border-radius: 100px;
      background: linear-gradient(90deg, #6FCF97, #2FA084);
      transition: width 0.6s ease;
    }
    .diff-fill.bad { background: linear-gradient(90deg, #ff6b6b, #cc4444); }

    /* ── HASH COMPARE ROWS ── */
    .hash-compare-row {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
      padding: 12px 16px;
    }
    .hcr-char {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      width: 16px;
      text-align: center;
      padding: 2px 0;
      border-radius: 3px;
    }
    .hcr-char.same  { color: #6FCF97; }
    .hcr-char.diff  { color: #ff6b6b; background: rgba(255,107,107,0.15); border-radius: 3px; }

    /* ── AVALANCHE SECTION ── */
    .avalanche-card {
      background: #0d1117;
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 14px;
      padding: 20px;
      margin-top: 16px;
    }
    .avalanche-title {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #4a7a6a;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 12px;
    }
    .avalanche-stat {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }
    .aval-num {
      font-family: 'Syne', sans-serif;
      font-size: 2.2rem;
      font-weight: 800;
      color: #ffd700;
      line-height: 1;
    }
    .aval-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #88aaaa;
      margin-top: 4px;
    }

    /* ── EXAMPLES TABLE ── */
    .example-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .example-table th {
      background: linear-gradient(135deg, var(--green-dark), var(--green-mid));
      color: white;
      padding: 10px 14px;
      text-align: left;
      font-weight: 600;
    }
    .example-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
    }
    .example-table tr:nth-child(even) td { background: rgba(111,207,151,0.04); }
    .example-table .td-text { color: var(--text-dark); font-size: 0.82rem; }
    .example-table .td-hash { color: var(--green-mid); word-break: break-all; font-size: 0.72rem; }
    .example-table tr { cursor: pointer; transition: background 0.15s; }
    .example-table tr:hover td { background: rgba(47,160,132,0.08); }

    /* ── INTEGRITY STATUS ── */
    .integrity-status {
      border-radius: 14px;
      padding: 24px;
      text-align: center;
      margin-bottom: 16px;
    }
    .integrity-status.valid {
      background: rgba(111,207,151,0.1);
      border: 2px solid var(--green-light);
    }
    .integrity-status.invalid {
      background: rgba(220,53,69,0.07);
      border: 2px solid #dc3545;
    }
    .integrity-icon { font-size: 3rem; margin-bottom: 10px; }
    .integrity-label {
      font-family: 'Syne', sans-serif;
      font-size: 1.3rem;
      font-weight: 800;
    }
    .integrity-label.valid-label  { color: var(--green-dark); }
    .integrity-label.invalid-label { color: #dc3545; }
    .integrity-sub {
      font-size: 0.85rem;
      color: var(--text-light);
      margin-top: 6px;
    }

    /* ── STATS ROW ── */
    .sha-stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .sha-stat-card {
      background: var(--white);
      border-radius: 14px;
      padding: 18px 16px;
      text-align: center;
      border: 1.5px solid var(--border);
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    }
    .sha-stat-num {
      font-family: 'Syne', sans-serif;
      font-size: 1.6rem;
      font-weight: 800;
      color: var(--green-mid);
      line-height: 1;
      display: block;
    }
    .sha-stat-lbl {
      font-size: 0.72rem;
      color: var(--text-light);
      margin-top: 5px;
    }

    /* ── FILE UPLOAD ── */
    .file-drop {
      border: 2px dashed var(--border);
      border-radius: 14px;
      padding: 32px 20px;
      text-align: center;
      transition: var(--transition);
      cursor: pointer;
    }
    .file-drop:hover { border-color: var(--green-mid); background: rgba(47,160,132,0.04); }
    .file-drop input { display: none; }

    /* ── COPY BUTTON ── */
    .copy-hash-btn {
      background: rgba(111,207,151,0.1);
      border: 1px solid rgba(111,207,151,0.25);
      color: #6FCF97;
      padding: 5px 14px;
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      cursor: pointer;
      transition: var(--transition);
    }
    .copy-hash-btn:hover { background: rgba(111,207,151,0.22); }

    /* Responsive */
    @media (max-width: 768px) {
      .sha-stats { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 480px) {
      .sha-stats { grid-template-columns: 1fr 1fr; }
      .byte-grid { gap: 3px; }
      .byte-cell { width: 28px; }
      .byte-hex  { width: 24px; height: 24px; font-size: 0.6rem; }
    }
  </style>
</head>
<body>

<!-- ═══ NAVBAR ═══ -->
<nav class="navbar">
  <a class="navbar-brand" href="index.php">
    <div class="brand-icon">🔐</div>KriptoVall
  </a>
  <ul class="navbar-nav" id="navMenu">
    <li><a href="index.php">🏠 Home</a></li>
    <li><a href="kalkulator-fpb.php">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="sha256-generator.php" class="active">#️⃣ SHA-256</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()"><span></span><span></span><span></span></button>
</nav>

<!-- ═══ PAGE HEADER ═══ -->
<div class="page-header">
  <div class="page-header-inner">
    <h1>#️⃣ SHA-256 Hashing Generator</h1>
    <p>Hash teks, file, HMAC, perbandingan hash, dan verifikasi integritas data — dengan visualisasi avalanche effect</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a><span>›</span><span>SHA-256 Generator</span>
    </div>
  </div>
</div>

<div class="container section">

  <!-- ═══ STATS ROW ═══ -->
  <div class="sha-stats">
    <div class="sha-stat-card">
      <span class="sha-stat-num">256</span>
      <div class="sha-stat-lbl">Output Bits</div>
    </div>
    <div class="sha-stat-card">
      <span class="sha-stat-num">64</span>
      <div class="sha-stat-lbl">Hex Characters</div>
    </div>
    <div class="sha-stat-card">
      <span class="sha-stat-num">32</span>
      <div class="sha-stat-lbl">Bytes Output</div>
    </div>
    <div class="sha-stat-card">
      <span class="sha-stat-num">2<sup style="font-size:0.9rem">256</sup></span>
      <div class="sha-stat-lbl">Possible Hashes</div>
    </div>
  </div>

  <!-- ═══ MODE TABS ═══ -->
  <div class="mode-tabs" id="modeTabs">
    <button class="mode-tab <?= ($mode === 'text')       ? 'active' : '' ?>"
            onclick="switchMode('text')">📝 Text Hash</button>
    <button class="mode-tab <?= ($mode === 'hmac')       ? 'active' : '' ?>"
            onclick="switchMode('hmac')">🔐 HMAC-SHA256</button>
    <button class="mode-tab <?= ($mode === 'compare')    ? 'active' : '' ?>"
            onclick="switchMode('compare')">🔍 Compare Hash</button>
    <button class="mode-tab <?= ($mode === 'file')       ? 'active' : '' ?>"
            onclick="switchMode('file')">📂 File Hash</button>
    <button class="mode-tab <?= ($mode === 'integrity')  ? 'active' : '' ?>"
            onclick="switchMode('integrity')">🛡️ Integrity Check</button>
  </div>

  <!-- ─────────────────────────────────────── -->
  <!-- MAIN TWO-COLUMN LAYOUT                  -->
  <!-- ─────────────────────────────────────── -->
  <div class="two-col">

    <!-- ═══ FORM KIRI ═══ -->
    <div>

      <?php if ($error): ?>
      <div class="alert alert-danger" style="margin-bottom:16px;">⚠️ <?= htmlspecialchars($error) ?></div>
      <?php endif; ?>

      <!-- ── FORM: TEXT HASH ── -->
      <div class="card" id="form-text" style="<?= $mode !== 'text' ? 'display:none' : '' ?>">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:18px;color:var(--text-dark);">
          📝 Text Hashing
        </h2>
        <form method="POST">
          <input type="hidden" name="mode" value="text">
          <div class="form-group">
            <label>Teks Input</label>
            <textarea name="text" rows="5" placeholder="Masukkan teks untuk di-hash..."><?= htmlspecialchars($_POST['text'] ?? '') ?></textarea>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;">#️⃣ Generate SHA-256</button>
        </form>

        <!-- Quick examples -->
        <div style="margin-top:18px;">
          <div style="font-size:0.78rem;font-weight:600;color:var(--text-light);margin-bottom:8px;">⚡ Contoh Cepat:</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <?php foreach (['Hello, World!', 'password123', 'KriptoVall', ''] as $ex): ?>
            <button class="mode-tab" style="padding:5px 12px;font-size:0.75rem;"
                    onclick="fillText(<?= json_encode($ex ?: 'abc') ?>)">
              <?= $ex ?: 'abc' ?>
            </button>
            <?php endforeach; ?>
          </div>
        </div>
      </div>

      <!-- ── FORM: HMAC ── -->
      <div class="card" id="form-hmac" style="<?= $mode !== 'hmac' ? 'display:none' : '' ?>">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:18px;color:var(--text-dark);">
          🔐 HMAC-SHA256
        </h2>
        <form method="POST">
          <input type="hidden" name="mode" value="hmac">
          <div class="form-group">
            <label>Pesan</label>
            <textarea name="hmac_text" rows="4" placeholder="Pesan yang ingin di-authenticate..."><?= htmlspecialchars($_POST['hmac_text'] ?? '') ?></textarea>
          </div>
          <div class="form-group">
            <label>Secret Key</label>
            <input type="text" name="hmac_key" placeholder="Kunci rahasia HMAC..."
              value="<?= htmlspecialchars($_POST['hmac_key'] ?? '') ?>">
            <div style="font-size:0.75rem;color:var(--text-light);margin-top:5px;">
              HMAC membuktikan keaslian pesan — hanya pengirim yang tahu kunci yang bisa membuat HMAC valid
            </div>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;">🔐 Generate HMAC</button>
        </form>
      </div>

      <!-- ── FORM: COMPARE ── -->
      <div class="card" id="form-compare" style="<?= $mode !== 'compare' ? 'display:none' : '' ?>">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:18px;color:var(--text-dark);">
          🔍 Bandingkan Hash
        </h2>
        <form method="POST">
          <input type="hidden" name="mode" value="compare">
          <div class="form-group">
            <label>Teks 1</label>
            <textarea name="text1" rows="3" placeholder="Teks pertama..."><?= htmlspecialchars($_POST['text1'] ?? '') ?></textarea>
          </div>
          <div class="form-group">
            <label>Teks 2</label>
            <textarea name="text2" rows="3" placeholder="Teks kedua (coba ubah satu huruf saja!)..."><?= htmlspecialchars($_POST['text2'] ?? '') ?></textarea>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;">🔍 Bandingkan</button>
        </form>
      </div>

      <!-- ── FORM: FILE HASH ── -->
      <div class="card" id="form-file" style="<?= $mode !== 'file' ? 'display:none' : '' ?>">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:18px;color:var(--text-dark);">
          📂 File Hashing
        </h2>
        <form method="POST" enctype="multipart/form-data">
          <input type="hidden" name="mode" value="file">
          <div class="file-drop" onclick="document.getElementById('fileInput').click()">
            <div style="font-size:3rem;margin-bottom:12px;">📂</div>
            <div style="font-weight:600;color:var(--text-dark);margin-bottom:6px;">Klik untuk pilih file</div>
            <div style="font-size:0.82rem;color:var(--text-light);">Semua tipe file didukung — max 10MB</div>
            <input type="file" id="fileInput" name="hashfile" onchange="updateFileName(this)" style="display:none">
            <div id="fileName" style="margin-top:10px;font-size:0.82rem;color:var(--green-mid);font-family:'JetBrains Mono',monospace;"></div>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;margin-top:16px;">📂 Hash File</button>
        </form>
      </div>

      <!-- ── FORM: INTEGRITY ── -->
      <div class="card" id="form-integrity" style="<?= $mode !== 'integrity' ? 'display:none' : '' ?>">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:18px;color:var(--text-dark);">
          🛡️ Verifikasi Integritas
        </h2>
        <form method="POST">
          <input type="hidden" name="mode" value="integrity">
          <div class="form-group">
            <label>Data / Teks yang Diterima</label>
            <textarea name="int_text" rows="4" placeholder="Masukkan data yang ingin diverifikasi..."><?= htmlspecialchars($_POST['int_text'] ?? '') ?></textarea>
          </div>
          <div class="form-group">
            <label>Hash SHA-256 yang Diketahui (64 char hex)</label>
            <input type="text" name="int_hash"
              placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              value="<?= htmlspecialchars($_POST['int_hash'] ?? '') ?>"
              style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">
            <div style="font-size:0.75rem;color:var(--text-light);margin-top:5px;">
              Masukkan hash SHA-256 yang dikeluarkan pengirim untuk verifikasi keaslian data
            </div>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;">🛡️ Verifikasi</button>
        </form>
      </div>

      <!-- ── INFO: APA ITU SHA-256 ── -->
      <div class="card" style="margin-top:20px;">
        <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:14px;color:var(--green-dark);">
          📖 Tentang SHA-256
        </h3>
        <div style="font-size:0.85rem;color:var(--text-light);line-height:1.8;">
          <strong style="color:var(--text-dark);">SHA-256</strong> (Secure Hash Algorithm 256-bit) adalah fungsi hash
          kriptografi dari keluarga SHA-2. Menghasilkan output <strong>256 bit (32 byte / 64 hex char)</strong>
          yang unik dan deterministik dari input apapun.
        </div>
        <div class="output-box" style="margin-top:14px;font-size:0.78rem;">
<span class="comment">// Sifat SHA-256:</span>
<span class="label">Deterministic  :</span> <span class="value">Input sama → hash selalu sama</span>
<span class="label">One-way        :</span> <span class="value">Tidak bisa di-reverse</span>
<span class="label">Avalanche      :</span> <span class="value">1 bit berubah → ~50% bit hash berubah</span>
<span class="label">Collision-free :</span> <span class="value">Hampir mustahil dua input → hash sama</span>
<span class="label">Fixed output   :</span> <span class="value">Selalu 256 bit, berapapun input</span>
        </div>
      </div>

    </div><!-- end form kiri -->

    <!-- ═══ OUTPUT KANAN ═══ -->
    <div>
      <?php if ($result): ?>

      <!-- ══════════════ OUTPUT: TEXT HASH ══════════════ -->
      <?php if ($result['mode'] === 'text'): ?>

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <h2 style="font-size:1.05rem;font-weight:700;color:var(--text-dark);">#️⃣ SHA-256 Hash</h2>
          <span class="result-badge badge-success">✅ Generated</span>
        </div>

        <!-- Input preview -->
        <div style="background:rgba(47,160,132,0.06);border:1.5px solid var(--green-light);border-radius:12px;padding:12px 16px;margin-bottom:14px;">
          <div style="font-size:0.72rem;color:var(--text-light);margin-bottom:4px;">INPUT (<?= $result['input_bytes'] ?> bytes)</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.88rem;color:var(--text-dark);word-break:break-all;">
            "<?= htmlspecialchars(substr($result['input'], 0, 120)) ?><?= strlen($result['input']) > 120 ? '…' : '' ?>"
          </div>
        </div>

        <!-- Hash Hex -->
        <div class="hash-display-wrap">
          <div class="hash-display-bar">
            <span class="hash-display-label">SHA-256 (Hexadecimal)</span>
            <button class="copy-hash-btn" onclick="copyText('hashHex',this)">📋 Copy</button>
          </div>
          <div class="hash-display-body" id="hashHex"><?= $result['hash_hex'] ?></div>
        </div>

        <!-- Hash formats -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
          <div class="hash-display-wrap" style="margin-bottom:0;">
            <div class="hash-display-bar">
              <span class="hash-display-label">Uppercase</span>
              <button class="copy-hash-btn" onclick="copyText('hashUpper',this)">📋</button>
            </div>
            <div class="hash-display-body" id="hashUpper" style="font-size:0.72rem;"><?= $result['hash_upper'] ?></div>
          </div>
          <div class="hash-display-wrap" style="margin-bottom:0;">
            <div class="hash-display-bar">
              <span class="hash-display-label">Base64</span>
              <button class="copy-hash-btn" onclick="copyText('hashB64',this)">📋</button>
            </div>
            <div class="hash-display-body alt" id="hashB64" style="font-size:0.72rem;"><?= $result['hash_b64'] ?></div>
          </div>
        </div>

        <!-- Spaced bytes -->
        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Byte-spaced (32 bytes)</span>
            <button class="copy-hash-btn" onclick="copyText('hashSpaced',this)">📋</button>
          </div>
          <div class="hash-display-body warn" id="hashSpaced" style="font-size:0.75rem;letter-spacing:1px;">
            <?= $result['hash_spaced'] ?>
          </div>
        </div>

        <!-- Byte grid visualisation -->
        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Visualisasi 32 Byte (Byte Grid)</span>
          </div>
          <div class="byte-grid">
            <?php foreach ($result['blocks'] as $i => $block): ?>
            <div class="byte-cell">
              <div class="byte-hex same" title="Byte <?= $i+1 ?>: 0x<?= $block['hex'] ?> = <?= $block['dec'] ?>"><?= $block['hex'] ?></div>
              <div class="byte-idx"><?= str_pad($i+1,2,'0',STR_PAD_LEFT) ?></div>
            </div>
            <?php endforeach; ?>
          </div>
        </div>

        <!-- AVALANCHE EFFECT -->
        <?php if ($result['hash_tweaked']): ?>
        <div class="avalanche-card">
          <div class="avalanche-title">⚡ Avalanche Effect — 1 Bit Input Diubah</div>
          <div class="avalanche-stat">
            <div>
              <div class="aval-num"><?= $result['diff_count'] ?><span style="font-size:1rem;color:#aaa;">/64</span></div>
              <div class="aval-label">hex chars berbeda</div>
            </div>
            <div style="text-align:right;">
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#6FCF97;">Original</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#ff8888;margin-top:4px;">Tweaked</div>
            </div>
          </div>
          <div class="diff-bar">
            <div class="diff-fill" style="width:<?= round($result['diff_count']/64*100) ?>%"></div>
          </div>
          <div style="font-size:0.72rem;color:#4a7a6a;margin-bottom:10px;text-align:right;">
            <?= round($result['diff_count']/64*100) ?>% karakter hex berubah
          </div>
          <!-- char-by-char diff -->
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#3a5a4a;margin-bottom:6px;">Original:</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff_bits'][$i]) && $result['diff_bits'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['hash_hex'][$i] ?></span>
            <?php endfor; ?>
          </div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#5a3a3a;margin:8px 0 6px;">Tweaked (+1 bit):</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff_bits'][$i]) && $result['diff_bits'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['hash_tweaked'][$i] ?></span>
            <?php endfor; ?>
          </div>
        </div>
        <?php endif; ?>


      <!-- ══════════════ OUTPUT: HMAC ══════════════ -->
      <?php elseif ($result['mode'] === 'hmac'): ?>

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <h2 style="font-size:1.05rem;font-weight:700;color:var(--text-dark);">🔐 HMAC-SHA256</h2>
          <span class="result-badge badge-success">✅ Generated</span>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
          <div style="background:rgba(47,160,132,0.06);border:1.5px solid var(--green-light);border-radius:10px;padding:12px;">
            <div style="font-size:0.7rem;color:var(--text-light);margin-bottom:4px;">PESAN</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:var(--text-dark);word-break:break-all;">
              "<?= htmlspecialchars(substr($result['input'],0,40)) ?><?= strlen($result['input'])>40?'…':'' ?>"
            </div>
          </div>
          <div style="background:rgba(220,53,69,0.06);border:1.5px solid rgba(220,53,69,0.3);border-radius:10px;padding:12px;">
            <div style="font-size:0.7rem;color:var(--text-light);margin-bottom:4px;">SECRET KEY</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:#ff8888;word-break:break-all;">
              "<?= htmlspecialchars($result['key']) ?>"
            </div>
          </div>
        </div>

        <div class="hash-display-wrap">
          <div class="hash-display-bar">
            <span class="hash-display-label">HMAC-SHA256 (Hex)</span>
            <button class="copy-hash-btn" onclick="copyText('hmacHex',this)">📋 Copy</button>
          </div>
          <div class="hash-display-body" id="hmacHex"><?= $result['hmac_hex'] ?></div>
        </div>

        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">HMAC-SHA256 (Base64)</span>
            <button class="copy-hash-btn" onclick="copyText('hmacB64',this)">📋 Copy</button>
          </div>
          <div class="hash-display-body alt" id="hmacB64" style="font-size:0.78rem;"><?= $result['hmac_b64'] ?></div>
        </div>

        <!-- Wrong key comparison -->
        <div class="avalanche-card">
          <div class="avalanche-title">🔑 HMAC dengan Kunci Salah (key + "x")</div>
          <div style="margin-bottom:8px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#3a5a4a;margin-bottom:4px;">Kunci benar "<?= htmlspecialchars($result['key']) ?>":</div>
            <div class="hash-compare-row">
              <?php for ($i = 0; $i < 64; $i++):
                $cls = (isset($result['diff_bits'][$i]) && $result['diff_bits'][$i]) ? 'diff' : 'same'; ?>
              <span class="hcr-char <?= $cls ?>"><?= $result['hmac_hex'][$i] ?></span>
              <?php endfor; ?>
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#5a3a3a;margin:8px 0 4px;">Kunci salah "<?= htmlspecialchars($result['key']) ?>x":</div>
            <div class="hash-compare-row">
              <?php for ($i = 0; $i < 64; $i++):
                $cls = (isset($result['diff_bits'][$i]) && $result['diff_bits'][$i]) ? 'diff' : 'same'; ?>
              <span class="hcr-char <?= $cls ?>"><?= $result['hmac_wrong_key'][$i] ?></span>
              <?php endfor; ?>
            </div>
          </div>
          <div class="alert alert-info" style="font-size:0.82rem;margin-top:10px;margin-bottom:0;">
            🔑 <strong><?= $result['diff_count'] ?>/64</strong> karakter berbeda —
            HMAC dengan kunci berbeda menghasilkan nilai yang <strong>sama sekali berbeda</strong>
          </div>
        </div>


      <!-- ══════════════ OUTPUT: COMPARE ══════════════ -->
      <?php elseif ($result['mode'] === 'compare'): ?>

        <div style="margin-bottom:16px;">
          <h2 style="font-size:1.05rem;font-weight:700;color:var(--text-dark);">🔍 Hasil Perbandingan Hash</h2>
        </div>

        <!-- Status badge -->
        <?php if ($result['match']): ?>
        <div class="alert alert-success" style="margin-bottom:16px;font-size:0.95rem;">
          ✅ <strong>Hash IDENTIK</strong> — Kedua teks menghasilkan SHA-256 yang sama
        </div>
        <?php else: ?>
        <div class="alert alert-danger" style="margin-bottom:16px;font-size:0.95rem;">
          ❌ <strong>Hash BERBEDA</strong> — <?= $result['changed'] ?>/64 karakter berbeda (<?= round($result['changed']/64*100) ?>%)
        </div>
        <?php endif; ?>

        <!-- Hash 1 -->
        <div class="hash-display-wrap" style="margin-bottom:10px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Hash Teks 1</span>
            <button class="copy-hash-btn" onclick="copyText('cmpH1',this)">📋</button>
          </div>
          <div class="hash-display-body" id="cmpH1"><?= $result['hash1'] ?></div>
        </div>

        <!-- Hash 2 -->
        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Hash Teks 2</span>
            <button class="copy-hash-btn" onclick="copyText('cmpH2',this)">📋</button>
          </div>
          <div class="hash-display-body" id="cmpH2"><?= $result['hash2'] ?></div>
        </div>

        <!-- Char diff -->
        <div class="avalanche-card">
          <div class="avalanche-title">🔬 Perbandingan Karakter (merah = berbeda)</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#3a5a4a;margin-bottom:4px;">Hash 1:</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff'][$i]) && $result['diff'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['hash1'][$i] ?></span>
            <?php endfor; ?>
          </div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#5a3a3a;margin:8px 0 4px;">Hash 2:</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff'][$i]) && $result['diff'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['hash2'][$i] ?></span>
            <?php endfor; ?>
          </div>
          <?php if (!$result['match']): ?>
          <div class="diff-bar" style="margin-top:12px;">
            <div class="diff-fill bad" style="width:<?= round($result['changed']/64*100) ?>%"></div>
          </div>
          <div style="font-size:0.72rem;color:#aaa;text-align:right;margin-top:4px;">
            <?= $result['changed'] ?> / <?= $result['total'] ?> karakter berbeda
          </div>
          <?php endif; ?>
        </div>


      <!-- ══════════════ OUTPUT: FILE ══════════════ -->
      <?php elseif ($result['mode'] === 'file'): ?>

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <h2 style="font-size:1.05rem;font-weight:700;color:var(--text-dark);">📂 File Hash Result</h2>
          <span class="result-badge badge-success">✅ Hashed</span>
        </div>

        <div style="background:rgba(47,160,132,0.06);border:1.5px solid var(--green-light);border-radius:12px;padding:14px 16px;margin-bottom:14px;">
          <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;">
            <div>
              <div style="font-size:0.72rem;color:var(--text-light);">Nama File</div>
              <div style="font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--text-dark);">
                <?= $result['filename'] ?>
              </div>
            </div>
            <div>
              <div style="font-size:0.72rem;color:var(--text-light);">Ukuran</div>
              <div style="font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--text-dark);">
                <?= number_format($result['filesize']) ?> bytes
                (<?= round($result['filesize']/1024, 2) ?> KB)
              </div>
            </div>
          </div>
        </div>

        <div class="hash-display-wrap" style="margin-bottom:10px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">SHA-256 (Hex)</span>
            <button class="copy-hash-btn" onclick="copyText('fileHashHex',this)">📋 Copy</button>
          </div>
          <div class="hash-display-body" id="fileHashHex"><?= $result['hash_hex'] ?></div>
        </div>

        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Base64</span>
            <button class="copy-hash-btn" onclick="copyText('fileHashB64',this)">📋</button>
          </div>
          <div class="hash-display-body alt" id="fileHashB64" style="font-size:0.78rem;"><?= $result['hash_b64'] ?></div>
        </div>

        <div class="output-box" style="font-size:0.8rem;">
<span class="comment">// ===== FILE SHA-256 HASH =====</span>
<span class="label">File      :</span> <span class="highlight"><?= $result['filename'] ?></span>
<span class="label">Size      :</span> <span class="value"><?= number_format($result['filesize']) ?> bytes</span>
<span class="label">Algorithm :</span> <span class="value">SHA-256 (hash_file)</span>
<span class="success">Hash(hex) : <?= $result['hash_hex'] ?></span>
        </div>


      <!-- ══════════════ OUTPUT: INTEGRITY ══════════════ -->
      <?php elseif ($result['mode'] === 'integrity'): ?>

        <div class="integrity-status <?= $result['valid'] ? 'valid' : 'invalid' ?>">
          <div class="integrity-icon"><?= $result['valid'] ? '✅' : '❌' ?></div>
          <div class="integrity-label <?= $result['valid'] ? 'valid-label' : 'invalid-label' ?>">
            <?= $result['valid'] ? 'DATA VALID / TIDAK DIMODIFIKASI' : 'DATA TIDAK VALID / DIMODIFIKASI' ?>
          </div>
          <div class="integrity-sub">
            <?= $result['valid']
              ? 'Hash yang dihitung cocok dengan hash yang diketahui — data asli.'
              : $result['changed'] . '/64 karakter hash berbeda — data telah dimanipulasi!' ?>
          </div>
        </div>

        <div class="hash-display-wrap" style="margin-bottom:10px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Hash Dihitung (dari data yang diterima)</span>
          </div>
          <div class="hash-display-body <?= $result['valid'] ? '' : 'alt' ?>"><?= $result['computed'] ?></div>
        </div>

        <div class="hash-display-wrap" style="margin-bottom:14px;">
          <div class="hash-display-bar">
            <span class="hash-display-label">Hash Diketahui (dari pengirim)</span>
          </div>
          <div class="hash-display-body"><?= $result['known'] ?></div>
        </div>

        <?php if (!$result['valid']): ?>
        <div class="avalanche-card">
          <div class="avalanche-title">🔬 Perbedaan Hash (merah = tidak cocok)</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#3a5a4a;margin-bottom:4px;">Computed:</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff'][$i]) && $result['diff'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['computed'][$i] ?></span>
            <?php endfor; ?>
          </div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#3a5a4a;margin:8px 0 4px;">Known:</div>
          <div class="hash-compare-row">
            <?php for ($i = 0; $i < 64; $i++):
              $cls = (isset($result['diff'][$i]) && $result['diff'][$i]) ? 'diff' : 'same'; ?>
            <span class="hcr-char <?= $cls ?>"><?= $result['known'][$i] ?></span>
            <?php endfor; ?>
          </div>
        </div>
        <?php endif; ?>

        <div class="output-box" style="margin-top:14px;font-size:0.8rem;">
<span class="comment">// ===== INTEGRITY CHECK =====</span>
<span class="label">Input      :</span> <span class="highlight">"<?= htmlspecialchars(substr($result['input'],0,40)) ?><?= strlen($result['input'])>40?'…':'' ?>"</span>
<span class="label">Computed   :</span> <span class="value"><?= $result['computed'] ?></span>
<span class="label">Known      :</span> <span class="value"><?= $result['known'] ?></span>
<span class="label">Match      :</span> <span class="<?= $result['valid'] ? 'success' : 'error' ?>"><?= $result['valid'] ? '✅ COCOK — Data Asli' : '❌ TIDAK COCOK — Data Dimodifikasi' ?></span>
        </div>

      <?php endif; ?>

      <?php else: ?>

      <!-- ══════════════ IDLE / PLACEHOLDER ══════════════ -->
      <div style="background:#0d1117;border-radius:20px;min-height:460px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;border:1px solid rgba(255,255,255,0.06);">
        <div style="font-size:4rem;opacity:0.3;">#️⃣</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;color:#2a4a3a;text-align:center;">
          Pilih mode dan masukkan data<br>untuk generate SHA-256 hash
        </div>
      </div>

      <!-- Quick demo examples -->
      <div class="card" style="margin-top:20px;">
        <h3 style="font-size:0.9rem;font-weight:700;margin-bottom:14px;color:var(--text-dark);">
          ⚡ Contoh Hash SHA-256
        </h3>
        <div style="overflow-x:auto;border-radius:10px;border:1px solid var(--border);">
          <table class="example-table">
            <thead>
              <tr><th>Input</th><th>SHA-256 Hash</th></tr>
            </thead>
            <tbody>
              <?php foreach ($examples as $ex): ?>
              <tr onclick="fillTextAndSubmit(<?= json_encode($ex['text']) ?>)">
                <td class="td-text"><?= htmlspecialchars($ex['text']) ?></td>
                <td class="td-hash"><?= $ex['hash'] ?></td>
              </tr>
              <?php endforeach; ?>
              <tr onclick="fillTextAndSubmit('')">
                <td class="td-text">(string kosong "")</td>
                <td class="td-hash"><?= hash('sha256','') ?></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div style="font-size:0.75rem;color:var(--text-light);margin-top:8px;">
          💡 Klik baris untuk langsung hash teks tersebut
        </div>
      </div>

      <?php endif; ?>
    </div><!-- end output kanan -->

  </div><!-- end two-col -->

  <!-- ═══ CARA KERJA SHA-256 ═══ -->
  <div style="margin-top:48px;">
    <h2 class="section-title">⚙️ Bagaimana SHA-256 Bekerja?</h2>
    <div class="about-grid">
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">🔄</div>
          <h3>Pre-processing</h3>
        </div>
        <p>Input di-<em>pad</em> hingga panjangnya ≡ 448 mod 512 bit. Kemudian ditambahkan 64-bit representasi panjang input asli. Total menjadi kelipatan 512 bit.</p>
      </div>
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">🧱</div>
          <h3>Message Schedule</h3>
        </div>
        <p>Setiap blok 512-bit dipecah menjadi 16 word 32-bit, lalu diperluas menjadi 64 word menggunakan operasi bitwise (shift, rotate, XOR).</p>
      </div>
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">🔁</div>
          <h3>64 Rounds</h3>
        </div>
        <p>8 variabel state (a–h) diproses melalui 64 putaran kompresi menggunakan konstanta K[0..63] dan fungsi Ch, Maj, Σ₀, Σ₁ berbasis bitwise.</p>
      </div>
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">➕</div>
          <h3>Update & Output</h3>
        </div>
        <p>Setelah 64 round, state ditambahkan ke nilai hash sebelumnya. Setelah semua blok diproses, 8 variabel state digabung → hash 256-bit final.</p>
      </div>
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">⚡</div>
          <h3>Avalanche Effect</h3>
        </div>
        <p>Mengubah <strong>1 bit input</strong> menghasilkan hash yang <strong>~50% bit-nya berbeda</strong>. Ini menjamin tidak ada korelasi antara input dan output.</p>
      </div>
      <div class="about-card">
        <div class="about-card-header">
          <div class="about-card-icon">🛡️</div>
          <h3>Kegunaan SHA-256</h3>
        </div>
        <p>Digunakan dalam: Sertifikat TLS/SSL, Bitcoin blockchain, verifikasi integritas file, penyimpanan password (dikombinasikan dengan salt), dan HMAC.</p>
      </div>
    </div>
  </div>

</div><!-- end container -->

<footer class="footer">
  <div class="footer-logo">🔐</div>
  <p><strong><a href="index.php">KriptoVall</a></strong> Tugas-tugas dari Mata Kuliah Kriptografi</p>
  <p style="margin-top: 8px; font-size: 0.8rem; opacity: 0.6;">Built with PHP Native · HTML5 · CSS3 · JavaScript</p>
</footer>

<script>
function toggleNav() {
  document.getElementById('navMenu').classList.toggle('open');
}

/* ── Mode switching ── */
function switchMode(m) {
  var forms = ['text','hmac','compare','file','integrity'];
  forms.forEach(function(f) {
    var el = document.getElementById('form-'+f);
    if (el) el.style.display = (f === m) ? '' : 'none';
  });
  document.querySelectorAll('.mode-tab').forEach(function(btn,i) {
    btn.classList.toggle('active', i === forms.indexOf(m));
  });
}

/* ── Fill text field ── */
function fillText(txt) {
  var ta = document.querySelector('#form-text textarea[name="text"]');
  if (ta) ta.value = txt;
}

/* ── Fill text and auto-submit ── */
function fillTextAndSubmit(txt) {
  switchMode('text');
  fillText(txt);
  setTimeout(function() {
    var form = document.querySelector('#form-text form');
    if (form) form.submit();
  }, 80);
}

/* ── Copy to clipboard ── */
function copyText(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.tagName === 'TEXTAREA' ? el.value : el.innerText;
  navigator.clipboard.writeText(text.trim()).then(function() {
    var orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    setTimeout(function() { btn.textContent = orig; }, 2000);
  }).catch(function() {
    if (el.tagName === 'TEXTAREA') { el.select(); document.execCommand('copy'); }
  });
}

/* ── File name display ── */
function updateFileName(input) {
  var d = document.getElementById('fileName');
  if (d && input.files[0]) d.textContent = '📄 ' + input.files[0].name + ' (' + (input.files[0].size/1024).toFixed(1) + ' KB)';
}

/* ── Live SHA-256 (JS fallback, for textarea preview) ── */
// (Uses SubtleCrypto for instant feedback while typing)
var liveTimeout;
var textArea = document.querySelector('#form-text textarea[name="text"]');
if (textArea) {
  textArea.addEventListener('input', function() {
    clearTimeout(liveTimeout);
    liveTimeout = setTimeout(function() {
      var text = textArea.value;
      if (!text || !window.crypto || !window.crypto.subtle) return;
      var encoder = new TextEncoder();
      window.crypto.subtle.digest('SHA-256', encoder.encode(text)).then(function(buf) {
        var bytes = Array.from(new Uint8Array(buf));
        var hex = bytes.map(function(b) { return b.toString(16).padStart(2,'0'); }).join('');
        var preview = document.getElementById('liveHashPreview');
        if (preview) {
          preview.textContent = hex;
          preview.style.display = '';
        }
      });
    }, 300);
  });
}

/* ── Country field auto-uppercase ── */
document.querySelectorAll('input[name="country"]').forEach(function(el) {
  el.addEventListener('input', function() { this.value = this.value.toUpperCase(); });
});
</script>
</body>
</html>