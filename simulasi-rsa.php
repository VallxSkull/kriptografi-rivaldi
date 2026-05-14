<?php
// simulasi-rsa.php — Simulasi RSA Encryption & Decryption

// ============================================================
// HELPER: Temukan path openssl.cnf (penting untuk Windows)
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

    // Glob semua versi PHP di Laragon
    foreach ((array) glob('C:/laragon/bin/php/*/extras/ssl/openssl.cnf') as $p) {
        $candidates[] = $p;
    }
    // Glob WAMP
    foreach ((array) glob('C:/wamp64/bin/php/*/extras/ssl/openssl.cnf') as $p) {
        $candidates[] = $p;
    }

    // Environment variable
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
// STEP 1: Generate RSA Key Pair untuk Alice
// ============================================================
$opensslCfg        = getOpensslConfig();
$openssl_error     = null;
$alice_private_key = null;
$alice_public_key  = null;

$resource = openssl_pkey_new($opensslCfg);

if ($resource === false) {
    $errs = [];
    while ($m = openssl_error_string()) $errs[] = $m;
    $openssl_error = $errs ? implode(' | ', $errs) : 'openssl_pkey_new() gagal. Periksa konfigurasi OpenSSL.';
} else {
    openssl_pkey_export($resource, $alice_private_key, null, $opensslCfg);
    $kd = openssl_pkey_get_details($resource);
    $alice_public_key = $kd['key'] ?? null;
}

// ============================================================
// STEP 2 & 3: Enkripsi (Bob) & Dekripsi (Alice)
// ============================================================
$plaintext_bob     = "Transfer ke Budi: Rp 100.000";
$encrypted         = '';
$ciphertext_base64 = '';
$decrypted         = '';
$decrypt_success   = false;

if ($alice_public_key && $alice_private_key) {
    openssl_public_encrypt($plaintext_bob, $encrypted, $alice_public_key);
    $ciphertext_base64 = base64_encode($encrypted);
    openssl_private_decrypt($encrypted, $decrypted, $alice_private_key);
    $decrypt_success = ($decrypted === $plaintext_bob);
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Simulasi RSA - KriptoVall</title>
  <link rel="stylesheet" href="style.css">
  <style>
    .rsa-step {
      background: var(--white);
      border-radius: var(--radius);
      padding: 28px;
      border: 1.5px solid var(--border);
      box-shadow: var(--shadow);
      position: relative;
    }
    .step-number {
      position: absolute; top: -14px; left: 20px;
      background: linear-gradient(135deg, var(--green-mid), var(--green-dark));
      color: white; width: 28px; height: 28px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 0.82rem; font-weight: 700;
    }
    .rsa-flow { display: flex; flex-direction: column; gap: 32px; }
    .arrow-down { text-align: center; font-size: 1.5rem; color: var(--green-mid); }
    .person-tag {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 12px; border-radius: 100px;
      font-size: 0.8rem; font-weight: 600; margin-bottom: 12px;
    }
    .tag-alice { background: rgba(111,207,151,0.15); color: var(--green-dark); border: 1px solid var(--green-light); }
    .tag-bob   { background: rgba(47,160,132,0.10); color: var(--green-mid);   border: 1px solid var(--green-mid); }
    .key-box {
      background: #0f1a17; border-radius: 8px; padding: 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
      color: var(--green-light); border: 1px solid rgba(111,207,151,0.2);
      word-break: break-all; line-height: 1.6; max-height: 110px; overflow-y: auto;
    }
    .cipher-box {
      background: #0f1a17; border-radius: 8px; padding: 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
      color: #ffd700; border: 1px solid rgba(255,215,0,0.2);
      word-break: break-all; line-height: 1.6; max-height: 120px; overflow-y: auto;
    }
    .error-solution {
      background: #1a0f0f; border: 1.5px solid #dc3545; border-radius: var(--radius-sm);
      padding: 20px; font-family: 'JetBrains Mono', monospace;
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
    <li><a href="simulasi-rsa.php" class="active">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️SSL Generator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()"><span></span><span></span><span></span></button>
</nav>

<div class="page-header">
  <div class="page-header-inner">
    <h1>🔑 Simulasi RSA</h1>
    <p>Simulasi enkripsi asimetris RSA: Generate key pair, enkripsi dengan public key, dekripsi dengan private key</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a><span>›</span><span>Simulasi RSA</span>
    </div>
  </div>
</div>

<div class="container section">

<?php if ($openssl_error): ?>

  <!-- ===== OPENSSL ERROR ===== -->
  <div class="alert alert-danger" style="margin-bottom:16px;">
    ⚠️ <strong>OpenSSL gagal generate key pair.</strong>
    Ini umum terjadi di Windows karena path <code>openssl.cnf</code> tidak ditemukan secara otomatis.
  </div>
  <div class="error-solution">
<span style="color:#ff6b6b;font-weight:700;">❌ Error:</span> <?= htmlspecialchars($openssl_error) ?>

<span style="color:#ffd700;font-weight:700;">✅ Solusi Laragon/XAMPP Windows:</span>

<span style="color:#aaa;">— Cek versi PHP Anda di: <code>C:\laragon\bin\php\</code></span>

<strong>Opsi 1 — Environment Variable (termudah):</strong>
  Set System Environment Variable:
  <code>OPENSSL_CONF = C:\laragon\bin\php\phpX.X.X\extras\ssl\openssl.cnf</code>
  Lalu restart Laragon.

<strong>Opsi 2 — php.ini:</strong>
  Buka php.ini aktif (klik kanan tray Laragon → PHP → php.ini)
  Pastikan tidak ada titik koma di depan:
  <code>extension=openssl</code>
  Tambahkan di bagian [openssl]:
  <code>openssl.cafile = "C:/laragon/bin/php/phpX.X.X/extras/ssl/cacert.pem"</code>
  Restart Laragon setelah simpan.

<strong>Opsi 3 — Gunakan php_binary path ini saat runtime:</strong>
  PHP Binary: <code><?= htmlspecialchars(PHP_BINARY) ?></code>
  Cari <code>openssl.cnf</code> di folder <code>extras/ssl/</code> dekat direktori tersebut.
  </div>

<?php else: ?>

  <!-- ===== INFO HEADER ===== -->
  <div class="alert alert-info" style="margin-bottom:32px;">
    🔄 <strong>Simulasi berjalan otomatis setiap halaman di-refresh.</strong>
    Key pair RSA baru dibangkitkan setiap kali!
    <?php if (isset($opensslCfg['config'])): ?>
    <span style="display:block;margin-top:5px;font-size:0.78rem;opacity:0.85;">
      ✅ OpenSSL config: <code><?= htmlspecialchars($opensslCfg['config']) ?></code>
    </span>
    <?php endif; ?>
  </div>

  <div class="two-col">

    <!-- FLOW SIMULASI -->
    <div class="rsa-flow">

      <!-- STEP 1 -->
      <div class="rsa-step">
        <div class="step-number">1</div>
        <div class="person-tag tag-alice">👩 Alice (Penerima)</div>
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-dark);">Generate RSA Key Pair</h3>

        <div style="margin-bottom:14px;">
          <div style="font-size:0.8rem;color:var(--text-light);margin-bottom:6px;">
            🌐 Public Key Alice <em>(dipublikasikan ke semua)</em>
          </div>
          <div class="key-box"><?= htmlspecialchars($alice_public_key ?? '') ?></div>
        </div>

        <div>
          <div style="font-size:0.8rem;color:var(--text-light);margin-bottom:6px;">
            🔒 Private Key Alice <em>(RAHASIA)</em>
          </div>
          <div class="key-box" style="color:#ff8888;"><?= htmlspecialchars($alice_private_key ?? '') ?></div>
        </div>

        <div class="alert alert-success" style="margin-top:14px;font-size:0.82rem;">
          ✅ Alice mempublikasikan <strong>Public Key</strong> agar siapa saja bisa mengirim pesan terenkripsi kepadanya
        </div>
      </div>

      <div class="arrow-down">⬇️</div>

      <!-- STEP 2 -->
      <div class="rsa-step">
        <div class="step-number">2</div>
        <div class="person-tag tag-bob">👨 Bob (Pengirim)</div>
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-dark);">Enkripsi dengan Public Key Alice</h3>

        <div style="margin-bottom:14px;">
          <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:6px;">📝 Plaintext:</div>
          <div style="background:rgba(47,160,132,0.08);border:1.5px solid var(--green-light);border-radius:10px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:0.9rem;color:var(--text-dark);">
            <?= htmlspecialchars($plaintext_bob) ?>
          </div>
        </div>

        <div style="text-align:center;color:var(--green-mid);font-size:0.85rem;margin:10px 0;">
          🔒 openssl_public_encrypt() ↓
        </div>

        <div>
          <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:6px;">🔐 Ciphertext (base64):</div>
          <div class="cipher-box"><?= htmlspecialchars($ciphertext_base64) ?></div>
        </div>

        <div class="alert alert-info" style="margin-top:14px;font-size:0.82rem;">
          💡 Hanya Alice yang bisa membaca — hanya Alice punya <strong>Private Key</strong>
        </div>
      </div>

      <div class="arrow-down">⬇️</div>

      <!-- STEP 3 -->
      <div class="rsa-step">
        <div class="step-number">3</div>
        <div class="person-tag tag-alice">👩 Alice (Penerima)</div>
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-dark);">Dekripsi dengan Private Key</h3>

        <div style="margin-bottom:14px;">
          <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:6px;">🔐 Ciphertext diterima:</div>
          <div class="cipher-box"><?= htmlspecialchars(substr($ciphertext_base64, 0, 80)) ?>...</div>
        </div>

        <div style="text-align:center;color:var(--green-mid);font-size:0.85rem;margin:10px 0;">
          🔓 openssl_private_decrypt() ↓
        </div>

        <div>
          <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:6px;">✅ Hasil Dekripsi:</div>
          <div style="background:rgba(111,207,151,0.12);border:2px solid var(--green-light);border-radius:10px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:0.95rem;color:var(--green-dark);font-weight:600;">
            <?= htmlspecialchars($decrypted ?: '—') ?>
          </div>
        </div>

        <?php if ($decrypt_success): ?>
        <div class="alert alert-success" style="margin-top:14px;">✅ <strong>Dekripsi Berhasil!</strong></div>
        <?php else: ?>
        <div class="alert alert-danger"  style="margin-top:14px;">❌ <strong>Dekripsi Gagal!</strong></div>
        <?php endif; ?>
      </div>

    </div><!-- end rsa-flow -->

    <!-- PANEL KANAN -->
    <div style="display:flex;flex-direction:column;gap:20px;">

      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-dark);">🧠 Bagaimana RSA Bekerja?</h3>
        <div style="display:flex;flex-direction:column;gap:10px;font-size:0.875rem;color:var(--text-light);">
          <?php
          $rsa_steps = [
            ['var(--green-dark)', '1', 'white', 'Alice men-generate <strong>Public Key</strong> (dibagikan) dan <strong>Private Key</strong> (rahasia)'],
            ['var(--green-mid)',  '2', 'white', 'Bob mengenkripsi pesan dengan <strong>Public Key Alice</strong>'],
            ['var(--green-light)','3', 'var(--green-dark)', 'Alice mendekripsi pesan dengan <strong>Private Key</strong>-nya'],
            ['#ffc107',          '✓', '#333',  'Bob sendiri <strong>tidak bisa mendekripsi</strong> — hanya pemilik private key!'],
          ];
          foreach ($rsa_steps as [$bg, $n, $fg, $desc]): ?>
          <div style="display:flex;gap:10px;align-items:flex-start;">
            <span style="background:<?= $bg ?>;color:<?= $fg ?>;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.75rem;flex-shrink:0;font-weight:700;"><?= $n ?></span>
            <span><?= $desc ?></span>
          </div>
          <?php endforeach; ?>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:14px;color:var(--text-dark);">💻 Output Lengkap</h3>
        <div class="output-box">
<span class="comment">// ===== SIMULASI RSA =====</span>

<span class="label">[ ALICE — Key Generation ]</span>
<span class="value">Key Size    :</span> <span class="highlight">2048 bit RSA</span>
<span class="value">Digest Alg  :</span> <span class="highlight">SHA-256</span>
<span class="value">Public Key  :</span> <span class="success">[Dipublikasikan ✓]</span>
<span class="value">Private Key :</span> <span class="error">[RAHASIA 🔒]</span>

<span class="label">[ BOB — Enkripsi ]</span>
<span class="value">Plaintext   :</span> <span class="highlight">"<?= htmlspecialchars($plaintext_bob) ?>"</span>
<span class="value">Ciphertext  :</span>
<span class="value"><?= wordwrap(substr($ciphertext_base64, 0, 80), 40, "\n", true) ?>...</span>

<span class="label">[ ALICE — Dekripsi ]</span>
<span class="value">Decrypted   :</span> <span class="highlight">"<?= htmlspecialchars($decrypted) ?>"</span>
<span class="<?= $decrypt_success ? 'success' : 'error' ?>">Status      : <?= $decrypt_success ? '✅ BERHASIL' : '❌ GAGAL' ?></span>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:10px;color:var(--text-dark);">🛡️ Matematika RSA</h3>
        <div class="output-box" style="font-size:0.78rem;">
<span class="comment">// Key Generation:</span>
<span class="highlight">p, q</span> = <span class="value">dua bilangan prima besar</span>
<span class="highlight">n</span>    = <span class="value">p × q  (modulus publik)</span>
<span class="highlight">φ(n)</span> = <span class="value">(p-1)(q-1)</span>
<span class="highlight">e</span>    = <span class="value">gcd(e, φ(n)) = 1</span>
<span class="highlight">d</span>    = <span class="value">e⁻¹ mod φ(n)</span>

<span class="success">Public Key  : (e, n)</span>
<span class="error">Private Key : (d, n)</span>

<span class="comment">// Enkripsi: C = M^e mod n</span>
<span class="comment">// Dekripsi: M = C^d mod n</span>
        </div>
      </div>

      <a href="simulasi-rsa.php" class="btn btn-primary" style="justify-content:center;">
        🔄 Generate Key Pair Baru
      </a>

    </div>

  </div><!-- end two-col -->

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