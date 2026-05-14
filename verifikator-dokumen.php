<?php
// verifikator-dokumen.php — Verifikator Dokumen Digital + Simulasi MITM

// ============================================================
// HELPER: Temukan path openssl.cnf (penting untuk Windows/Laragon)
// ============================================================
function getOpensslConfig(): array {
    $config = [
        'digest_alg'       => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $phpDir = defined('PHP_BINARY') ? str_replace('\\','/',dirname(PHP_BINARY)) : '';

    $candidates = [
        $phpDir . '/extras/ssl/openssl.cnf',
        $phpDir . '/../extras/ssl/openssl.cnf',
        'C:/xampp/php/extras/ssl/openssl.cnf',
    ];

    foreach ((array) glob('C:/laragon/bin/php/*/extras/ssl/openssl.cnf') as $p) {
        $candidates[] = $p;
    }
    foreach ((array) glob('C:/wamp64/bin/php/*/extras/ssl/openssl.cnf') as $p) {
        $candidates[] = $p;
    }
    if (getenv('OPENSSL_CONF')) $candidates[] = getenv('OPENSSL_CONF');

    foreach ($candidates as $path) {
        $path = str_replace('\\', '/', (string)$path);
        if ($path !== '' && file_exists($path)) {
            $config['config'] = $path;
            break;
        }
    }
    return $config;
}

// ============================================================
// HELPER: Generate RSA key pair — returns false on failure
// ============================================================
function generateKeyPair(array $cfg): array|false {
    $resource = openssl_pkey_new($cfg);
    if ($resource === false) return false;

    $private_key = null;
    openssl_pkey_export($resource, $private_key, null, $cfg);

    $kd = openssl_pkey_get_details($resource);
    $public_key = $kd['key'] ?? null;

    if (!$private_key || !$public_key) return false;
    return ['private' => $private_key, 'public' => $public_key];
}

// ============================================================
// SETUP
// ============================================================
$step          = $_POST['step'] ?? 'menu';
$opensslCfg    = getOpensslConfig();
$openssl_error = null;
$output        = [];
$original_doc  = "Transfer ke Budi: Rp 100.000";

// ============================================================
// STEP: Generate Key
// ============================================================
if ($step === 'generate') {
    $keys = generateKeyPair($opensslCfg);
    if ($keys === false) {
        $errs = [];
        while ($m = openssl_error_string()) $errs[] = $m;
        $openssl_error = $errs ? implode(' | ', $errs) : 'openssl_pkey_new() gagal.';
        $step = 'error';
    } else {
        $output['public_key']  = $keys['public'];
        $output['private_key'] = $keys['private'];
    }
}

// ============================================================
// STEP: Sign Dokumen
// ============================================================
if ($step === 'sign') {
    $keys = generateKeyPair($opensslCfg);
    if ($keys === false) {
        $errs = [];
        while ($m = openssl_error_string()) $errs[] = $m;
        $openssl_error = $errs ? implode(' | ', $errs) : 'openssl_pkey_new() gagal.';
        $step = 'error';
    } else {
        $signature_raw = '';
        openssl_sign($original_doc, $signature_raw, $keys['private'], OPENSSL_ALGO_SHA256);

        $output['private_key']   = $keys['private'];
        $output['public_key']    = $keys['public'];
        $output['document']      = $original_doc;
        $output['signature_b64'] = base64_encode($signature_raw);
        $output['hash_doc']      = hash('sha256', $original_doc);
    }
}

// ============================================================
// STEP: Verifikasi + Simulasi MITM
// ============================================================
if ($step === 'verify') {
    $keys = generateKeyPair($opensslCfg);
    if ($keys === false) {
        $errs = [];
        while ($m = openssl_error_string()) $errs[] = $m;
        $openssl_error = $errs ? implode(' | ', $errs) : 'openssl_pkey_new() gagal.';
        $step = 'error';
    } else {
        $signature_raw = '';
        openssl_sign($original_doc, $signature_raw, $keys['private'], OPENSSL_ALGO_SHA256);

        // Simulasi MITM: ubah "Budi" -> "Andi"
        $modified_doc = str_replace('Budi', 'Andi', $original_doc);

        $verify_original = openssl_verify($original_doc, $signature_raw, $keys['public'], OPENSSL_ALGO_SHA256);
        $verify_modified = openssl_verify($modified_doc, $signature_raw, $keys['public'], OPENSSL_ALGO_SHA256);

        $output['public_key']      = $keys['public'];
        $output['private_key']     = $keys['private'];
        $output['document_orig']   = $original_doc;
        $output['document_mod']    = $modified_doc;
        $output['signature_b64']   = base64_encode($signature_raw);
        $output['verify_original'] = $verify_original; // 1 = valid
        $output['verify_modified'] = $verify_modified; // 0 = tidak valid
        $output['hash_original']   = hash('sha256', $original_doc);
        $output['hash_modified']   = hash('sha256', $modified_doc);
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifikator Dokumen - KriptoVall</title>
  <link rel="stylesheet" href="style.css">
  <style>
    .menu-card-ver {
      display: flex; align-items: center; gap: 16px;
      background: var(--white); border-radius: var(--radius);
      padding: 22px; border: 1.5px solid var(--border);
      box-shadow: var(--shadow); transition: var(--transition);
      text-decoration: none; color: inherit; width: 100%;
      text-align: left; cursor: pointer;
    }
    .menu-card-ver:hover {
      transform: translateY(-3px);
      box-shadow: var(--shadow-hover);
      border-color: var(--green-mid);
    }
    .menu-icon-ver {
      width: 52px; height: 52px; border-radius: 14px;
      background: linear-gradient(135deg, var(--green-light), var(--green-mid));
      display: flex; align-items: center; justify-content: center;
      font-size: 1.5rem; flex-shrink: 0;
    }
    .hash-compare { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0; }
    .hash-box {
      background: #0f1a17; border-radius: 10px; padding: 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
      word-break: break-all; line-height: 1.8;
    }
    .mitm-arrow {
      text-align: center; font-size: 0.9rem; color: #dc3545;
      background: rgba(220,53,69,0.08); padding: 10px; border-radius: 10px;
      border: 1px dashed #dc3545; margin: 12px 0;
    }
    .error-solution {
      background: #1a0f0f; border: 1.5px solid #dc3545;
      border-radius: var(--radius-sm); padding: 20px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem; color: #ffaaaa; line-height: 2;
    }
    .error-solution code {
      background: rgba(220,53,69,0.2); padding: 2px 6px;
      border-radius: 4px; color: #ffcccc;
    }
  </style>
</head>
<body>

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
    <li><a href="verifikator-dokumen.php" class="active">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()"><span></span><span></span><span></span></button>
</nav>

<div class="page-header">
  <div class="page-header-inner">
    <h1>📋 Verifikator Dokumen Digital</h1>
    <p>Simulasi tanda tangan digital, deteksi modifikasi dokumen, dan serangan Man-In-The-Middle</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a><span>›</span><span>Verifikator Dokumen</span>
    </div>
  </div>
</div>

<div class="container section">

<?php
// ============ ERROR TAMPILAN ============
if ($step === 'error' && $openssl_error):
?>
  <div class="alert alert-danger" style="margin-bottom:16px;">
    ⚠️ <strong>OpenSSL gagal generate key pair.</strong>
    Path <code>openssl.cnf</code> tidak ditemukan secara otomatis di sistem ini.
  </div>
  <div class="error-solution">
<span style="color:#ff6b6b;font-weight:700;">❌ Error:</span> <?= htmlspecialchars($openssl_error) ?>

<span style="color:#ffd700;font-weight:700;">✅ Solusi Laragon/XAMPP Windows:</span>

<span style="color:#aaa;">PHP Binary terdeteksi: <code><?= htmlspecialchars(PHP_BINARY) ?></code></span>

<strong>Opsi 1 — Environment Variable (paling mudah):</strong>
  Tambahkan System Environment Variable:
  <code>OPENSSL_CONF = C:\laragon\bin\php\phpX.X.X\extras\ssl\openssl.cnf</code>
  Ganti X.X.X dengan versi PHP Anda, lalu restart Laragon.

<strong>Opsi 2 — php.ini:</strong>
  Buka php.ini (klik kanan tray Laragon → PHP → php.ini)
  Pastikan aktif: <code>extension=openssl</code>
  Tambahkan di [openssl]: <code>openssl.cafile="C:/laragon/bin/php/phpX.X.X/extras/ssl/cacert.pem"</code>
  Restart Laragon.
  </div>

  <div style="margin-top:20px;">
    <form method="POST"><input type="hidden" name="step" value="menu">
      <button type="submit" class="btn btn-primary">← Kembali ke Menu</button>
    </form>
  </div>

<?php
// ============ MENU UTAMA ============
elseif ($step === 'menu'):
?>

  <div style="margin-bottom:32px;">
    <h2 class="section-title">📋 Pilih Operasi</h2>
    <p class="section-subtitle">Ikuti urutan: Generate Key → Tanda Tangani → Verifikasi</p>
  </div>

  <div style="display:flex;flex-direction:column;gap:16px;max-width:700px;">

    <form method="POST" action="">
      <input type="hidden" name="step" value="generate">
      <button type="submit" class="menu-card-ver">
        <div class="menu-icon-ver">🔑</div>
        <div>
          <div style="font-weight:700;font-size:1.05rem;color:var(--text-dark);">1. Generate Key Pair</div>
          <div style="font-size:0.875rem;color:var(--text-light);margin-top:4px;">
            Bangkitkan pasangan Public Key dan Private Key menggunakan OpenSSL RSA 2048-bit
          </div>
        </div>
        <div style="margin-left:auto;color:var(--green-mid);font-size:1.3rem;">→</div>
      </button>
    </form>

    <form method="POST" action="">
      <input type="hidden" name="step" value="sign">
      <button type="submit" class="menu-card-ver">
        <div class="menu-icon-ver">✍️</div>
        <div>
          <div style="font-weight:700;font-size:1.05rem;color:var(--text-dark);">2. Tanda Tangani Dokumen</div>
          <div style="font-size:0.875rem;color:var(--text-light);margin-top:4px;">
            Tanda tangani dokumen "<?= htmlspecialchars($original_doc) ?>" menggunakan Private Key
          </div>
        </div>
        <div style="margin-left:auto;color:var(--green-mid);font-size:1.3rem;">→</div>
      </button>
    </form>

    <form method="POST" action="">
      <input type="hidden" name="step" value="verify">
      <button type="submit" class="menu-card-ver">
        <div class="menu-icon-ver">🕵️</div>
        <div>
          <div style="font-weight:700;font-size:1.05rem;color:var(--text-dark);">3. Verifikasi + Simulasi MITM</div>
          <div style="font-size:0.875rem;color:var(--text-light);margin-top:4px;">
            Verifikasi dokumen asli (VALID) dan simulasi modifikasi "Budi → Andi" (TIDAK VALID)
          </div>
        </div>
        <div style="margin-left:auto;color:#dc3545;font-size:1.3rem;">→</div>
      </button>
    </form>

  </div>

  <div class="card" style="max-width:700px;margin-top:28px;">
    <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:12px;color:var(--green-dark);">
      📖 Cara Kerja Tanda Tangan Digital
    </h3>
    <div style="font-size:0.875rem;color:var(--text-light);line-height:1.8;">
      <strong style="color:var(--text-dark);">1.</strong> Penanda tangan membuat <strong>hash</strong> dokumen, lalu mengenkripsinya dengan <strong>Private Key</strong> → tanda tangan digital<br>
      <strong style="color:var(--text-dark);">2.</strong> Penerima mendekripsi tanda tangan dengan <strong>Public Key</strong> → mendapat hash A<br>
      <strong style="color:var(--text-dark);">3.</strong> Penerima juga membuat hash dari dokumen yang diterima → hash B<br>
      <strong style="color:var(--text-dark);">4.</strong> Jika hash A = hash B → dokumen <strong style="color:var(--green-dark);">VALID</strong>; jika tidak → dokumen <strong style="color:#dc3545;">DIPALSUKAN!</strong>
    </div>
  </div>


<?php
// ============ GENERATE KEY ============
elseif ($step === 'generate'):
?>

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
    <div>
      <h2 class="section-title">🔑 Generate RSA Key Pair</h2>
      <p style="color:var(--text-light);font-size:0.9rem;">Pasangan kunci RSA 2048-bit berhasil dibangkitkan</p>
    </div>
    <form method="POST"><input type="hidden" name="step" value="menu">
      <button type="submit" class="btn btn-outline">← Kembali</button>
    </form>
  </div>

  <div class="two-col">
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <span style="font-size:1.5rem;">🌐</span>
        <div>
          <div style="font-weight:700;color:var(--text-dark);">Public Key</div>
          <div style="font-size:0.78rem;color:var(--text-light);">Dapat disebarkan ke siapa saja</div>
        </div>
        <span class="result-badge badge-success" style="margin-left:auto;">Publik</span>
      </div>
      <div class="key-display"><?= htmlspecialchars($output['public_key']) ?></div>
    </div>
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <span style="font-size:1.5rem;">🔒</span>
        <div>
          <div style="font-weight:700;color:var(--text-dark);">Private Key</div>
          <div style="font-size:0.78rem;color:var(--text-light);">RAHASIA — jangan pernah dibagikan!</div>
        </div>
        <span class="result-badge badge-danger" style="margin-left:auto;">Rahasia</span>
      </div>
      <div class="key-display" style="color:#ff8888;"><?= htmlspecialchars($output['private_key']) ?></div>
    </div>
  </div>

  <div class="output-box" style="margin-top:20px;">
<span class="comment">// === GENERATE RSA KEY PAIR ===</span>
<span class="label">Fungsi    :</span> <span class="value">openssl_pkey_new(['private_key_bits' => 2048])</span>
<span class="label">Key Type  :</span> <span class="highlight">RSA 2048-bit</span>
<span class="label">Digest    :</span> <span class="highlight">SHA-256</span>
<span class="success">✅ Public Key  : [Generated — <?= strlen($output['public_key']) ?> bytes]</span>
<span class="error">🔒 Private Key : [Generated — <?= strlen($output['private_key']) ?> bytes — RAHASIA]</span>
  </div>

  <div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap;">
    <form method="POST"><input type="hidden" name="step" value="sign">
      <button type="submit" class="btn btn-primary">✍️ Lanjut ke Tanda Tangan →</button>
    </form>
    <form method="POST"><input type="hidden" name="step" value="generate">
      <button type="submit" class="btn btn-outline">🔄 Generate Ulang</button>
    </form>
  </div>


<?php
// ============ SIGN DOKUMEN ============
elseif ($step === 'sign'):
?>

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
    <div>
      <h2 class="section-title">✍️ Tanda Tangani Dokumen</h2>
      <p style="color:var(--text-light);font-size:0.9rem;">Dokumen ditandatangani dengan Private Key, algoritma SHA-256</p>
    </div>
    <form method="POST"><input type="hidden" name="step" value="menu">
      <button type="submit" class="btn btn-outline">← Kembali</button>
    </form>
  </div>

  <div class="two-col">
    <div style="display:flex;flex-direction:column;gap:20px;">

      <div class="card">
        <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:14px;color:var(--text-dark);">📄 Dokumen yang Ditandatangani</h3>
        <div style="background:rgba(111,207,151,0.08);border:2px solid var(--green-light);border-radius:12px;padding:20px;font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:var(--green-dark);text-align:center;">
          <?= htmlspecialchars($output['document']) ?>
        </div>
        <div style="margin-top:10px;font-size:0.8rem;color:var(--text-light);">
          Hash SHA-256:
          <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--green-mid);">
            <?= substr($output['hash_doc'], 0, 32) ?>...
          </span>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:12px;">⚙️ Proses Penandatanganan</h3>
        <div style="display:flex;flex-direction:column;gap:10px;font-size:0.85rem;">
          <?php
          $sign_steps = [
            ['var(--green-dark)', 'white', 'Buat hash SHA-256 dari dokumen'],
            ['var(--green-mid)',  'white', 'Enkripsi hash menggunakan Private Key RSA'],
            ['var(--green-light)','var(--green-dark)', 'Hasil enkripsi = Digital Signature'],
          ];
          foreach ($sign_steps as $i => [$bg, $fg, $desc]): ?>
          <div style="display:flex;gap:10px;align-items:center;">
            <span style="background:<?= $bg ?>;color:<?= $fg ?>;width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.75rem;flex-shrink:0;font-weight:700;"><?= $i+1 ?></span>
            <span><?= $desc ?></span>
          </div>
          <?php endforeach; ?>
        </div>
        <div style="margin-top:12px;font-size:0.78rem;background:rgba(47,160,132,0.06);padding:10px;border-radius:8px;font-family:'JetBrains Mono',monospace;color:var(--text-dark);">
          openssl_sign($doc, $sig, $private_key, OPENSSL_ALGO_SHA256)
        </div>
      </div>

    </div>

    <div>
      <div class="card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
          <span style="font-size:1.5rem;">🖊️</span>
          <div>
            <div style="font-weight:700;color:var(--text-dark);">Digital Signature (base64)</div>
            <div style="font-size:0.78rem;color:var(--text-light);">Dihasilkan dari Private Key + SHA-256</div>
          </div>
          <span class="result-badge badge-success" style="margin-left:auto;">✅ Signed</span>
        </div>
        <div class="key-display" style="color:#ffd700;max-height:160px;"><?= htmlspecialchars($output['signature_b64']) ?></div>
        <div style="margin-top:10px;font-size:0.78rem;color:var(--text-light);">
          Panjang signature: <?= strlen($output['signature_b64']) ?> karakter (base64)
        </div>
      </div>

      <div class="output-box" style="margin-top:16px;">
<span class="comment">// === DIGITAL SIGNATURE ===</span>
<span class="label">Dokumen   :</span> <span class="highlight">"<?= htmlspecialchars($output['document']) ?>"</span>
<span class="label">Algoritma :</span> <span class="value">OPENSSL_ALGO_SHA256</span>
<span class="label">Hash Doc  :</span> <span class="value"><?= substr($output['hash_doc'], 0, 32) ?>...</span>
<span class="success">✅ Signature dibuat [<?= strlen($output['signature_b64']) ?> chars base64]</span>
      </div>

      <div style="margin-top:16px;">
        <form method="POST"><input type="hidden" name="step" value="verify">
          <button type="submit" class="btn btn-primary" style="width:100%;">
            🕵️ Lanjut ke Verifikasi + Simulasi MITM →
          </button>
        </form>
      </div>
    </div>
  </div>


<?php
// ============ VERIFIKASI + MITM ============
elseif ($step === 'verify'):
?>

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
    <div>
      <h2 class="section-title">🕵️ Verifikasi + Simulasi MITM</h2>
      <p style="color:var(--text-light);font-size:0.9rem;">Dokumen asli vs dokumen yang dimodifikasi penyerang</p>
    </div>
    <form method="POST"><input type="hidden" name="step" value="menu">
      <button type="submit" class="btn btn-outline">← Kembali</button>
    </form>
  </div>

  <div class="alert alert-danger" style="margin-bottom:24px;">
    🚨 <strong>Simulasi Man-In-The-Middle!</strong>
    Penyerang mengubah <strong>"Budi"</strong> → <strong>"Andi"</strong> dalam dokumen transfer.
  </div>

  <div class="two-col">

    <!-- DOKUMEN ASLI (VALID) -->
    <div class="card" style="border:2px solid var(--green-light);">
      <div class="alert alert-success" style="margin-bottom:16px;">
        ✅ <strong>Dokumen ASLI — Verifikasi: VALID</strong>
      </div>
      <div style="background:rgba(111,207,151,0.08);border:2px solid var(--green-light);border-radius:12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:0.9rem;font-weight:600;color:var(--green-dark);margin-bottom:16px;text-align:center;">
        <?= htmlspecialchars($output['document_orig']) ?>
      </div>
      <div style="font-size:0.8rem;color:var(--text-light);margin-bottom:8px;">Hash SHA-256:</div>
      <div class="key-display" style="max-height:48px;font-size:0.72rem;color:var(--green-light);">
        <?= $output['hash_original'] ?>
      </div>
      <div class="output-box" style="margin-top:14px;font-size:0.78rem;">
<span class="comment">// openssl_verify()</span>
<span class="value">Dokumen  :</span> <span class="highlight">"<?= htmlspecialchars($output['document_orig']) ?>"</span>
<span class="value">Hash match: </span><span class="success">✓ Cocok</span>
<span class="success">STATUS   : ✅ DOKUMEN VALID</span>
      </div>
      <div style="margin-top:14px;text-align:center;">
        <div style="display:inline-flex;align-items:center;gap:8px;background:rgba(111,207,151,0.15);padding:12px 20px;border-radius:100px;border:2px solid var(--green-light);">
          <span style="font-size:1.5rem;">✅</span>
          <div>
            <div style="font-weight:700;color:var(--green-dark);">DOKUMEN VALID</div>
            <div style="font-size:0.75rem;color:var(--green-mid);">openssl_verify = <?= $output['verify_original'] ?></div>
          </div>
        </div>
      </div>
    </div>

    <!-- DOKUMEN TERMODIFIKASI (TIDAK VALID) -->
    <div class="card" style="border:2px solid #dc3545;">
      <div class="alert alert-danger" style="margin-bottom:16px;">
        🚨 <strong>Dokumen DIMODIFIKASI — Verifikasi: TIDAK VALID</strong>
      </div>
      <div class="mitm-arrow">
        🕵️ Penyerang mengubah: <strong>"Budi"</strong> → <strong>"Andi"</strong>
      </div>
      <div style="background:rgba(220,53,69,0.06);border:2px solid #dc3545;border-radius:12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:0.9rem;font-weight:600;color:#dc3545;margin-bottom:16px;text-align:center;">
        <?= htmlspecialchars($output['document_mod']) ?>
      </div>
      <div style="font-size:0.8rem;color:var(--text-light);margin-bottom:8px;">Hash SHA-256 (berbeda!):</div>
      <div class="key-display" style="max-height:48px;font-size:0.72rem;color:#ff8888;">
        <?= $output['hash_modified'] ?>
      </div>
      <div class="output-box" style="margin-top:14px;font-size:0.78rem;">
<span class="comment">// openssl_verify()</span>
<span class="value">Dokumen  :</span> <span class="error">"<?= htmlspecialchars($output['document_mod']) ?>"</span>
<span class="value">Hash match: </span><span class="error">✗ Tidak cocok</span>
<span class="error">STATUS   : ❌ DOKUMEN TIDAK VALID</span>
      </div>
      <div style="margin-top:14px;text-align:center;">
        <div style="display:inline-flex;align-items:center;gap:8px;background:rgba(220,53,69,0.1);padding:12px 20px;border-radius:100px;border:2px solid #dc3545;">
          <span style="font-size:1.5rem;">❌</span>
          <div>
            <div style="font-weight:700;color:#dc3545;">DOKUMEN TIDAK VALID</div>
            <div style="font-size:0.75rem;color:#dc3545;">openssl_verify = <?= $output['verify_modified'] ?></div>
          </div>
        </div>
      </div>
    </div>

  </div>

  <!-- HASH COMPARISON -->
  <div class="card" style="margin-top:20px;">
    <h3 style="font-size:1rem;font-weight:700;margin-bottom:14px;color:var(--text-dark);">
      🔬 Perbandingan Hash SHA-256
    </h3>
    <p style="font-size:0.875rem;color:var(--text-light);margin-bottom:14px;">
      Perubahan satu kata saja menghasilkan hash yang <strong>sangat berbeda</strong> — inilah avalanche effect dari fungsi hash.
    </p>
    <div class="hash-compare">
      <div class="hash-box" style="border:1px solid rgba(111,207,151,0.3);">
        <div style="color:#6FCF97;font-weight:700;margin-bottom:8px;">✅ Hash Asli ("Budi"):</div>
        <div style="color:#a8e6c5;"><?= $output['hash_original'] ?></div>
      </div>
      <div class="hash-box" style="border:1px solid rgba(220,53,69,0.3);">
        <div style="color:#ff8888;font-weight:700;margin-bottom:8px;">❌ Hash Dimodifikasi ("Andi"):</div>
        <div style="color:#ff8888;"><?= $output['hash_modified'] ?></div>
      </div>
    </div>
    <div class="alert alert-danger" style="font-size:0.875rem;">
      🔍 <strong>Kesimpulan:</strong> Hanya satu kata yang berubah ("Budi" → "Andi") namun hash SHA-256 menghasilkan nilai <strong>sama sekali berbeda</strong>.
      Verifikasi signature <strong>GAGAL</strong> → Serangan MITM <strong>TERDETEKSI!</strong>
    </div>
  </div>

  <!-- FULL OUTPUT -->
  <div class="output-box" style="margin-top:20px;">
<span class="comment">// ===== VERIFIKASI DOKUMEN DIGITAL =====</span>

<span class="label">Dokumen Asli  :</span> <span class="highlight">"<?= htmlspecialchars($output['document_orig']) ?>"</span>
<span class="label">Algoritma     :</span> <span class="highlight">RSA + SHA-256</span>
<span class="label">Signature     :</span> <span class="value">[<?= strlen($output['signature_b64']) ?> chars base64]</span>

<span class="label">[ MITM ATTACK ]</span>
<span class="error">Penyerang ubah: "Budi" → "Andi"</span>
<span class="error">Dokumen Palsu : "<?= htmlspecialchars($output['document_mod']) ?>"</span>

<span class="label">[ VERIFIKASI ]</span>
<span class="success">✅ Dokumen Asli    : VALID   (openssl_verify = <?= $output['verify_original'] ?>)</span>
<span class="error">❌ Dokumen Diubah  : TIDAK VALID (openssl_verify = <?= $output['verify_modified'] ?>)</span>

<span class="success">🛡️ Digital Signature berhasil mendeteksi pemalsuan dokumen!</span>
  </div>

  <div style="margin-top:20px;">
    <form method="POST"><input type="hidden" name="step" value="verify">
      <button type="submit" class="btn btn-primary">🔄 Jalankan Simulasi Ulang</button>
    </form>
  </div>

<?php endif; ?>

</div>

<footer class="footer">
  <div class="footer-logo">🔐</div>
  <p><strong><a href="index.php">KriptoVall</a></strong> Tugas-tugas dari Mata Kuliah Kriptografi</p>
  <p style="margin-top: 8px; font-size: 0.8rem; opacity: 0.6;">Built with PHP Native · HTML5 · CSS3 · JavaScript</p>
</footer>
<script>
function toggleNav() {
  document.getElementById('navMenu').classList.toggle('open');
}
</script>
</body>
</html>