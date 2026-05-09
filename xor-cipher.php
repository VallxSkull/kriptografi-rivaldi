<?php
// xor-cipher.php — XOR Cipher dengan visualisasi Binary + Hexadecimal

$result = null;
$error  = null;

/* -------------------------------------------------------
 * XOR Cipher — kunci diulang sepanjang teks
 * ------------------------------------------------------- */
function xor_process(string $text, string $key): string {
    $out = '';
    $kl  = strlen($key);
    for ($i = 0; $i < strlen($text); $i++) {
        $out .= chr(ord($text[$i]) ^ ord($key[$i % $kl]));
    }
    return $out;
}

/* Konversi string → representasi binary (spasi antar byte) */
function to_bin(string $s): string {
    $parts = [];
    for ($i = 0; $i < strlen($s); $i++) {
        $parts[] = str_pad(decbin(ord($s[$i])), 8, '0', STR_PAD_LEFT);
    }
    return implode(' ', $parts);
}

/* Konversi string → uppercase hex, dipisahkan spasi */
function to_hex(string $s): string {
    $parts = [];
    for ($i = 0; $i < strlen($s); $i++) {
        $parts[] = strtoupper(bin2hex($s[$i]));
    }
    return implode(' ', $parts);
}

// ---- Proses POST ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mode  = $_POST['mode']  ?? 'encrypt';
    $input = $_POST['input'] ?? '';
    $key   = $_POST['key']   ?? '';

    if (trim($input) === '') {
        $error = 'Input teks tidak boleh kosong!';
    } elseif (trim($key) === '') {
        $error = 'Kunci XOR tidak boleh kosong!';
    } else {

        if ($mode === 'encrypt') {
            // ── ENKRIPSI: teks → XOR → hex ──
            $plain      = $input;
            $key_rep    = substr(str_repeat($key, (int)ceil(strlen($plain)/strlen($key))), 0, strlen($plain));
            $cipher_raw = xor_process($plain, $key);
            $hex_out    = to_hex($cipher_raw);

            $result = [
                'mode'       => 'encrypt',
                'input'      => $plain,
                'key'        => $key,
                'key_rep'    => $key_rep,
                'output_hex' => $hex_out,
                'output_raw' => $cipher_raw,
                'plain_raw'  => $plain,
            ];

        } else {
            // ── DEKRIPSI: hex → XOR → teks ──
            $clean = preg_replace('/\s+/', '', $input);
            if (!ctype_xdigit($clean) || strlen($clean) % 2 !== 0) {
                $error = 'Input dekripsi harus berupa hex valid (contoh: 3A 1F 2B).';
            } else {
                $cipher_raw = hex2bin($clean);
                $key_rep    = substr(str_repeat($key, (int)ceil(strlen($cipher_raw)/strlen($key))), 0, strlen($cipher_raw));
                $plain      = xor_process($cipher_raw, $key);

                $result = [
                    'mode'       => 'decrypt',
                    'input'      => $input,
                    'key'        => $key,
                    'key_rep'    => $key_rep,
                    'output_hex' => '',
                    'output_raw' => $plain,
                    'plain_raw'  => $cipher_raw,
                ];
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
  <title>XOR Cipher - KriptoVall</title>
  <link rel="stylesheet" href="style.css">
  <style>
    /* ── Binary visualisation grid ── */
    .bin-grid {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .bin-row {
      display: grid;
      grid-template-columns: 72px 1fr auto;
      align-items: center;
      gap: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
    }
    .bin-row-label {
      color: #888;
      white-space: nowrap;
    }
    .bin-row-bits {
      letter-spacing: 1px;
      word-break: break-all;
    }
    .bin-row-meta {
      color: #666;
      font-size: 0.72rem;
      white-space: nowrap;
    }
    .bin-divider {
      border: none;
      border-top: 1px dashed #2a4a3a;
      margin: 4px 0;
    }
    .bin-wrap {
      background: #0f1a17;
      border: 1px solid rgba(111,207,151,0.15);
      border-radius: 10px;
      padding: 16px 18px;
      overflow-x: auto;
    }
    .bin-char-header {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #555;
      margin-bottom: 10px;
    }
    /* ── Hex strip ── */
    .hex-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      padding: 14px;
      background: #0f1a17;
      border: 1px solid rgba(255,215,0,0.2);
      border-radius: 10px;
    }
    .hex-byte {
      background: rgba(255,215,0,0.1);
      border: 1px solid rgba(255,215,0,0.25);
      color: #ffd700;
      padding: 3px 7px;
      border-radius: 5px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      font-weight: 600;
    }
    /* ── IO comparison ── */
    .io-row {
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
    }
    .io-box {
      background: rgba(111,207,151,0.05);
      border: 1.5px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }
    .io-box.io-out {
      background: linear-gradient(135deg, rgba(111,207,151,0.1), rgba(47,160,132,0.06));
      border-color: var(--green-light);
    }
    .io-label {
      font-size: 0.72rem;
      color: var(--text-light);
      margin-bottom: 6px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .io-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-dark);
      word-break: break-all;
    }
    .io-value.io-cipher { color: #ffd700; }
    .io-value.io-plain  { color: var(--green-dark); }
    .io-arrow {
      text-align: center;
      font-size: 1.1rem;
      color: var(--green-mid);
    }
    /* ── Key repeat visualization ── */
    .key-map {
      display: flex;
      flex-wrap: wrap;
      gap: 3px;
      margin-top: 8px;
    }
    .key-char {
      background: rgba(47,160,132,0.15);
      border: 1px solid rgba(47,160,132,0.3);
      color: var(--green-mid);
      width: 24px;
      height: 24px;
      border-radius: 5px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      font-weight: 700;
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
    <li><a href="xor-cipher.php" class="active">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()"><span></span><span></span><span></span></button>
</nav>

<div class="page-header">
  <div class="page-header-inner">
    <h1>⊕ XOR Cipher</h1>
    <p>Enkripsi dan dekripsi teks menggunakan operasi XOR bitwise — visualisasi binary dan hexadecimal</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a><span>›</span><span>XOR Cipher</span>
    </div>
  </div>
</div>

<div class="container section">
  <div class="two-col">

    <!-- ═══════════════ FORM KIRI ═══════════════ -->
    <div style="display:flex;flex-direction:column;gap:20px;">

      <div class="card">
        <h2 style="font-size:1.1rem;font-weight:700;margin-bottom:20px;color:var(--text-dark);">
          ⊕ XOR Cipher Tool
        </h2>

        <form method="POST" action="">

          <?php if ($error): ?>
          <div class="alert alert-danger">⚠️ <?= htmlspecialchars($error) ?></div>
          <?php endif; ?>

          <!-- MODE -->
          <div class="form-group">
            <label>Mode Operasi</label>
            <div class="radio-group">
              <div class="radio-option">
                <input type="radio" name="mode" id="mode_enc" value="encrypt"
                  <?= (($_POST['mode'] ?? 'encrypt') === 'encrypt') ? 'checked' : '' ?>
                  onchange="updateLabels(this.value)">
                <label for="mode_enc">🔒 Enkripsi</label>
              </div>
              <div class="radio-option">
                <input type="radio" name="mode" id="mode_dec" value="decrypt"
                  <?= (($_POST['mode'] ?? '') === 'decrypt') ? 'checked' : '' ?>
                  onchange="updateLabels(this.value)">
                <label for="mode_dec">🔓 Dekripsi</label>
              </div>
            </div>
          </div>

          <!-- INPUT -->
          <div class="form-group">
            <label for="input" id="lbl_input">📝 Plaintext</label>
            <textarea id="input" name="input" rows="4"
              placeholder="Masukkan teks untuk dienkripsi..."
            ><?= htmlspecialchars($_POST['input'] ?? '') ?></textarea>
            <div id="hint_input" style="font-size:0.75rem;color:var(--text-light);margin-top:5px;">
              Tulis teks bebas — semua karakter bisa diproses
            </div>
          </div>

          <!-- KEY -->
          <div class="form-group">
            <label for="key">🗝️ Kunci XOR</label>
            <input type="text" id="key" name="key" placeholder="Contoh: SECRET"
              value="<?= htmlspecialchars($_POST['key'] ?? '') ?>">
            <div style="font-size:0.75rem;color:var(--text-light);margin-top:5px;">
              Kunci diulang otomatis mengikuti panjang teks
            </div>
          </div>

          <button type="submit" class="btn btn-primary" style="width:100%;">⚡ Proses XOR</button>

        </form>
      </div>

      <!-- XOR TRUTH TABLE -->
      <div class="card">
        <h3 style="font-size:0.9rem;font-weight:700;margin-bottom:12px;color:var(--green-dark);">
          📊 Tabel Kebenaran XOR
        </h3>
        <table class="step-table" style="font-size:0.85rem;max-width:220px;">
          <thead>
            <tr><th>A</th><th>B</th><th>A ⊕ B</th></tr>
          </thead>
          <tbody>
            <tr><td>0</td><td>0</td><td style="color:var(--green-mid);font-weight:700;">0</td></tr>
            <tr><td>0</td><td>1</td><td style="color:#ffc107;font-weight:700;">1</td></tr>
            <tr><td>1</td><td>0</td><td style="color:#ffc107;font-weight:700;">1</td></tr>
            <tr><td>1</td><td>1</td><td style="color:var(--green-mid);font-weight:700;">0</td></tr>
          </tbody>
        </table>
        <div style="margin-top:12px;font-size:0.82rem;color:var(--text-light);line-height:1.8;">
          <strong>Sifat reversible:</strong> A ⊕ K ⊕ K = A<br>
          Proses enkripsi dan dekripsi identik — operasi yang sama!
        </div>
        <div class="output-box" style="margin-top:12px;font-size:0.8rem;">
<span class="label">Enkripsi:</span> <span class="highlight">C = P ⊕ K</span>
<span class="label">Dekripsi:</span> <span class="highlight">P = C ⊕ K</span>
<span class="comment">// Sama persis — XOR bersifat involusi</span>
        </div>
      </div>

    </div><!-- end form kiri -->

    <!-- ═══════════════ HASIL KANAN ═══════════════ -->
    <div>
      <?php if ($result): ?>

      <!-- ── BADGE HEADER ── -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
        <h2 style="font-size:1.1rem;font-weight:700;color:var(--text-dark);">
          <?= $result['mode'] === 'encrypt' ? '🔒 Hasil Enkripsi' : '🔓 Hasil Dekripsi' ?>
        </h2>
        <span class="result-badge badge-success">
          <?= $result['mode'] === 'encrypt' ? '⊕ XOR → Hex' : '⊕ Hex → Teks' ?>
        </span>
      </div>

      <!-- ── IO COMPARISON ── -->
      <div class="io-row">
        <div class="io-box">
          <div class="io-label"><?= $result['mode'] === 'encrypt' ? '📝 Input (Plaintext)' : '🔐 Input (Hex Cipher)' ?></div>
          <div class="io-value">
            <?= htmlspecialchars(mb_strlen($result['input']) > 40
                ? mb_substr($result['input'], 0, 40) . '…'
                : $result['input']) ?>
          </div>
        </div>
        <div class="io-arrow">⊕<br><span style="font-size:0.65rem;color:var(--text-light);">XOR</span></div>
        <div class="io-box io-out">
          <div class="io-label"><?= $result['mode'] === 'encrypt' ? '🔐 Output (Hex Cipher)' : '📝 Output (Plaintext)' ?></div>
          <div class="io-value <?= $result['mode'] === 'encrypt' ? 'io-cipher' : 'io-plain' ?>">
            <?php if ($result['mode'] === 'encrypt'): ?>
              <?= htmlspecialchars(strlen($result['output_hex']) > 50
                  ? substr($result['output_hex'], 0, 50) . '…'
                  : $result['output_hex']) ?>
            <?php else: ?>
              <?= htmlspecialchars(mb_strlen($result['output_raw']) > 40
                  ? mb_substr($result['output_raw'], 0, 40) . '…'
                  : $result['output_raw']) ?>
            <?php endif; ?>
          </div>
        </div>
      </div>

      <!-- ── OUTPUT BOX FULL ── -->
      <?php if ($result['mode'] === 'encrypt'): ?>
      <div style="margin-bottom:16px;">
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:8px;">
          🔐 Ciphertext — Hexadecimal Lengkap:
        </div>
        <div class="output-wrapper">
          <div class="output-box" id="hexOutput" style="color:#ffd700;font-size:0.82rem;line-height:2;">
<?= htmlspecialchars($result['output_hex']) ?>
          </div>
          <button class="copy-btn" onclick="copyEl('hexOutput',this)">📋 Copy</button>
        </div>
        <!-- Hex byte display -->
        <div style="margin-top:10px;">
          <div style="font-size:0.75rem;color:var(--text-light);margin-bottom:6px;">Byte per byte:</div>
          <div class="hex-strip">
            <?php foreach (explode(' ', $result['output_hex']) as $byte): ?>
            <span class="hex-byte"><?= htmlspecialchars($byte) ?></span>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
      <?php else: ?>
      <div style="margin-bottom:16px;">
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:8px;">
          📝 Hasil Dekripsi — Plaintext:
        </div>
        <div class="output-wrapper">
          <div class="output-box" id="plainOutput" style="color:var(--green-light);font-size:0.95rem;">
<?= htmlspecialchars($result['output_raw']) ?>
          </div>
          <button class="copy-btn" onclick="copyEl('plainOutput',this)">📋 Copy</button>
        </div>
      </div>
      <?php endif; ?>

      <!-- ── KUNCI INFO ── -->
      <div style="margin-bottom:16px;">
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:8px;">
          🗝️ Kunci "<strong><?= htmlspecialchars($result['key']) ?></strong>"
          diulang <?= strlen($result['key_rep']) ?> kali → <?= strlen($result['key_rep']) ?> karakter:
        </div>
        <div class="key-map">
          <?php
          $chars = str_split($result['key_rep']);
          $show  = array_slice($chars, 0, 36);
          foreach ($show as $c): ?>
          <div class="key-char"><?= htmlspecialchars($c) ?></div>
          <?php endforeach;
          if (count($chars) > 36): ?>
          <div class="key-char" style="background:transparent;border-color:transparent;color:#555;">+<?= count($chars)-36 ?></div>
          <?php endif; ?>
        </div>
      </div>

      <!-- ── BINARY VISUALISASI ── -->
      <?php
      $max_vis  = 4;
      $src      = $result['plain_raw'];
      $src_len  = min(strlen($src), $max_vis);
      ?>
      <div style="margin-bottom:16px;">
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-mid);margin-bottom:8px;">
          🔬 Visualisasi Bitwise (<?= $src_len ?> karakter pertama):
        </div>
        <div class="bin-wrap">
          <div class="bin-grid">
          <?php for ($i = 0; $i < $src_len; $i++):
            $pc  = $src[$i];
            $kc  = $result['key_rep'][$i % max(strlen($result['key_rep']),1)];
            $rc  = chr(ord($pc) ^ ord($kc));
            $pb  = str_pad(decbin(ord($pc)), 8, '0', STR_PAD_LEFT);
            $kb  = str_pad(decbin(ord($kc)), 8, '0', STR_PAD_LEFT);
            $rb  = str_pad(decbin(ord($rc)), 8, '0', STR_PAD_LEFT);
          ?>
            <div>
              <div class="bin-char-header">── Karakter <?= $i+1 ?> ──</div>
              <div class="bin-row">
                <span class="bin-row-label" style="color:#88ccaa;">
                  <?= $result['mode'] === 'encrypt' ? 'Plaintext' : 'Cipher' ?> [<?= htmlspecialchars($pc) ?>]
                </span>
                <span class="bin-row-bits" style="color:#a8e6c5;"><?= $pb ?></span>
                <span class="bin-row-meta"><?= ord($pc) ?> / 0x<?= strtoupper(dechex(ord($pc))) ?></span>
              </div>
              <div class="bin-row">
                <span class="bin-row-label" style="color:#88aaff;">Key [<?= htmlspecialchars($kc) ?>]</span>
                <span class="bin-row-bits" style="color:#aabbff;"><?= $kb ?></span>
                <span class="bin-row-meta"><?= ord($kc) ?> / 0x<?= strtoupper(dechex(ord($kc))) ?></span>
              </div>
              <hr class="bin-divider">
              <div class="bin-row">
                <span class="bin-row-label" style="color:#ffd700;">XOR ⊕ [<?= htmlspecialchars($rc) ?>]</span>
                <span class="bin-row-bits" style="color:#ffd700;font-weight:700;"><?= $rb ?></span>
                <span class="bin-row-meta"><?= ord($rc) ?> / 0x<?= strtoupper(dechex(ord($rc))) ?></span>
              </div>
            </div>
            <?php if ($i < $src_len - 1): ?>
            <hr class="bin-divider" style="border-color:#1a3a2a;">
            <?php endif; ?>
          <?php endfor; ?>
          <?php if (strlen($src) > $max_vis): ?>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#444;text-align:center;">
              … <?= strlen($src) - $max_vis ?> karakter lainnya tidak ditampilkan …
            </div>
          <?php endif; ?>
          </div>
        </div>
      </div>

      <!-- ── FLOW SUMMARY ── -->
      <div class="output-box" style="font-size:0.8rem;">
<?php if ($result['mode'] === 'encrypt'): ?>
<span class="comment">// ENKRIPSI XOR</span>
<span class="label">Plaintext :</span> <span class="highlight">"<?= htmlspecialchars(substr($result['input'],0,30)) ?><?= strlen($result['input'])>30?'…':'' ?>"</span>
<span class="label">Key       :</span> <span class="highlight">"<?= htmlspecialchars($result['key']) ?>"</span>
<span class="label">Key[rep]  :</span> <span class="value">"<?= htmlspecialchars(substr($result['key_rep'],0,30)) ?><?= strlen($result['key_rep'])>30?'…':'' ?>"</span>
<span class="comment">for i: cipher[i] = plain[i] ⊕ key[i % len(key)]</span>
<span class="success">Hex Output: <?= substr(str_replace(' ','',$result['output_hex']),0,40) ?><?= strlen($result['output_hex'])>40?'…':'' ?></span>
<?php else: ?>
<span class="comment">// DEKRIPSI XOR</span>
<span class="label">Hex Input :</span> <span class="highlight"><?= htmlspecialchars(substr($result['input'],0,30)) ?>…</span>
<span class="label">Key       :</span> <span class="highlight">"<?= htmlspecialchars($result['key']) ?>"</span>
<span class="comment">for i: plain[i] = cipher[i] ⊕ key[i % len(key)]</span>
<span class="success">Plaintext : "<?= htmlspecialchars($result['output_raw']) ?>"</span>
<?php endif; ?>
      </div>

      <?php else: ?>

      <!-- PLACEHOLDER -->
      <div class="card" style="text-align:center;padding:52px 28px;border:2px dashed var(--border);">
        <div style="font-size:4rem;margin-bottom:16px;">⊕</div>
        <h3 style="font-size:1rem;font-weight:600;color:var(--text-light);margin-bottom:10px;">XOR Cipher Siap Digunakan</h3>
        <p style="font-size:0.875rem;color:var(--text-light);margin-bottom:24px;max-width:300px;margin-left:auto;margin-right:auto;">
          Isi form di kiri: pilih mode, masukkan teks dan kunci, lalu klik ⚡ Proses XOR
        </p>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;background:rgba(47,160,132,0.06);border:1px solid var(--border);padding:16px;border-radius:12px;text-align:left;display:inline-block;min-width:260px;">
          <div style="color:var(--text-light);margin-bottom:8px;font-size:0.75rem;">Contoh:</div>
          Enkripsi: <span style="color:var(--green-mid);">P ⊕ K = C</span><br>
          Dekripsi: <span style="color:var(--green-mid);">C ⊕ K = P</span><br>
          <span style="color:#888;font-size:0.75rem;">"HELLO" ⊕ "KEY" → hex</span>
        </div>
      </div>

      <?php endif; ?>
    </div><!-- end kanan -->

  </div><!-- end two-col -->
</div>

<footer class="footer">
  <p><strong>KriptoVall</strong> Tugas-tugas dari Mata Kuliah Kriptografi</p>
  <p style="margin-top:8px;font-size:0.8rem;opacity:0.6;">Built with PHP Native · HTML5 · CSS3 · JavaScript</p>
</footer>

<script>
function toggleNav() {
  document.getElementById('navMenu').classList.toggle('open');
}

function updateLabels(mode) {
  var lbl   = document.getElementById('lbl_input');
  var ta    = document.getElementById('input');
  var hint  = document.getElementById('hint_input');
  if (mode === 'encrypt') {
    lbl.textContent  = '📝 Plaintext';
    ta.placeholder   = 'Masukkan teks untuk dienkripsi...';
    hint.textContent = 'Tulis teks bebas — semua karakter bisa diproses';
  } else {
    lbl.textContent  = '🔐 Ciphertext (Hex)';
    ta.placeholder   = 'Masukkan hex ciphertext... (contoh: 3A 1F 2B)';
    hint.textContent = 'Paste hex output dari proses enkripsi di atas';
  }
}

function copyEl(id, btn) {
  var text = document.getElementById(id).innerText.trim();
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = '✅ Copied!';
    setTimeout(function() { btn.textContent = '📋 Copy'; }, 2000);
  }).catch(function() {
    btn.textContent = '⚠️ Gagal';
    setTimeout(function() { btn.textContent = '📋 Copy'; }, 2000);
  });
}

// Set label sesuai POST state saat load
(function() {
  var dec = document.getElementById('mode_dec');
  if (dec && dec.checked) updateLabels('decrypt');
})();
</script>
</body>
</html>