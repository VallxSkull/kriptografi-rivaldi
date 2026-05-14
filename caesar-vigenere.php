<?php
// caesar-vigenere.php — Caesar Cipher & Vigenere Cipher

$result = null;
$error  = null;

/**
 * Caesar Cipher — menggeser huruf A-Z sebanyak $key posisi
 * Angka, spasi, dan simbol tidak berubah
 *
 * @param string $text         Teks input
 * @param int    $key          Jumlah pergeseran (0-25)
 * @param bool   $is_encrypt   true = enkripsi, false = dekripsi
 * @return array [result, steps]
 */
function caesar_cipher($text, $key, $is_encrypt) {
    $output = '';
    $steps  = [];
    $key    = $key % 26;
    if (!$is_encrypt) $key = (26 - $key) % 26; // Dekripsi = shift berlawanan

    $text_upper = strtoupper($text);

    for ($i = 0; $i < strlen($text_upper); $i++) {
        $char = $text_upper[$i];
        if (ctype_alpha($char)) {
            $original_pos = ord($char) - ord('A');
            $new_pos      = ($original_pos + $key) % 26;
            $new_char     = chr($new_pos + ord('A'));
            $output      .= $new_char;
            $steps[]      = [
                'original' => $char,
                'pos_orig' => $original_pos,
                'shift'    => $key,
                'pos_new'  => $new_pos,
                'result'   => $new_char,
                'formula'  => "({$original_pos} + {$key}) mod 26 = {$new_pos}"
            ];
        } else {
            $output .= $char;
            $steps[] = [
                'original' => $char,
                'pos_orig' => '-',
                'shift'    => '-',
                'pos_new'  => '-',
                'result'   => $char,
                'formula'  => 'tidak digeser'
            ];
        }
    }

    return ['result' => $output, 'steps' => $steps];
}

/**
 * Vigenere Cipher — menggeser tiap huruf menggunakan huruf kunci yang berulang
 *
 * @param string $text       Teks input
 * @param string $key        Kunci (hanya huruf A-Z)
 * @param bool   $is_encrypt true = enkripsi, false = dekripsi
 * @return array [result, steps]
 */
function vigenere_cipher($text, $key, $is_encrypt) {
    $output    = '';
    $steps     = [];
    $key       = strtoupper(preg_replace('/[^a-zA-Z]/', '', $key)); // hapus non-huruf dari kunci
    $text_up   = strtoupper($text);
    $key_index = 0;
    $key_len   = strlen($key);

    if ($key_len === 0) return ['result' => $text, 'steps' => []];

    for ($i = 0; $i < strlen($text_up); $i++) {
        $char = $text_up[$i];
        if (ctype_alpha($char)) {
            $p = ord($char) - ord('A');
            $k = ord($key[$key_index % $key_len]) - ord('A');

            if ($is_encrypt) {
                $c = ($p + $k) % 26;
                $formula = "({$p} + {$k}) mod 26 = {$c}";
            } else {
                $c = ($p - $k + 26) % 26;
                $formula = "({$p} - {$k} + 26) mod 26 = {$c}";
            }

            $new_char  = chr($c + ord('A'));
            $output   .= $new_char;
            $steps[]   = [
                'plain'     => $char,
                'key_char'  => $key[$key_index % $key_len],
                'p'         => $p,
                'k'         => $k,
                'c'         => $c,
                'result'    => $new_char,
                'formula'   => $formula,
                'key_idx'   => $key_index % $key_len,
            ];
            $key_index++;
        } else {
            $output .= $char;
            $steps[] = [
                'plain'    => $char,
                'key_char' => '-',
                'p'        => '-',
                'k'        => '-',
                'c'        => '-',
                'result'   => $char,
                'formula'  => 'tidak digeser',
                'key_idx'  => '-',
            ];
        }
    }

    return ['result' => $output, 'steps' => $steps];
}

// Proses POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $algo       = $_POST['algo']        ?? 'caesar';
    $action     = $_POST['action']      ?? 'encrypt';
    $plaintext  = $_POST['plaintext']   ?? '';
    $caesar_key = (int)($_POST['caesar_key'] ?? 3);
    $vig_key    = $_POST['vigenere_key'] ?? 'KEY';
    $is_enc     = ($action === 'encrypt');

    if (empty(trim($plaintext))) {
        $error = 'Teks tidak boleh kosong!';
    } else {
        if ($algo === 'caesar') {
            if ($caesar_key < 0 || $caesar_key > 25) {
                $error = 'Kunci Caesar harus antara 0 dan 25!';
            } else {
                $res = caesar_cipher($plaintext, $caesar_key, $is_enc);
                $result = [
                    'algo'      => 'caesar',
                    'action'    => $action,
                    'input'     => strtoupper($plaintext),
                    'key'       => $caesar_key,
                    'output'    => $res['result'],
                    'steps'     => $res['steps'],
                ];
            }
        } else {
            if (empty(trim($vig_key)) || !preg_match('/^[a-zA-Z]+$/', $vig_key)) {
                $error = 'Kunci Vigenere hanya boleh berisi huruf A-Z!';
            } else {
                $res = vigenere_cipher($plaintext, $vig_key, $is_enc);
                $result = [
                    'algo'      => 'vigenere',
                    'action'    => $action,
                    'input'     => strtoupper($plaintext),
                    'key'       => strtoupper($vig_key),
                    'output'    => $res['result'],
                    'steps'     => $res['steps'],
                ];
            }
        }
    }
}

// Generate tabel alfabet Caesar untuk ditampilkan
function caesar_alphabet_table($shift) {
    $rows = [];
    for ($i = 0; $i < 26; $i++) {
        $rows[] = [
            'plain'  => chr(65 + $i),
            'cipher' => chr(65 + ($i + $shift) % 26)
        ];
    }
    return $rows;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Caesar & Vigenere - KriptoVall</title>
  <link rel="stylesheet" href="style.css">
  <style>
    .caesar-wheel {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      margin-top: 12px;
    }
    .caesar-pair {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 28px;
    }
    .cp-orig {
      background: var(--green-dark);
      color: white;
      width: 28px;
      height: 28px;
      border-radius: 6px 6px 0 0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      font-weight: 700;
    }
    .cp-enc {
      background: var(--green-light);
      color: var(--green-dark);
      width: 28px;
      height: 28px;
      border-radius: 0 0 6px 6px;
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

<!-- NAVBAR -->
<nav class="navbar">
  <a class="navbar-brand" href="index.php">
    <div class="brand-icon">🔐</div>
    KriptoVall
  </a>
  <ul class="navbar-nav" id="navMenu">
    <li><a href="index.php">🏠 Home</a></li>
    <li><a href="kalkulator-fpb.php">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php" class="active">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- PAGE HEADER -->
<div class="page-header">
  <div class="page-header-inner">
    <h1>🔄 Caesar & Vigenère Cipher</h1>
    <p>Cipher klasik: Caesar dengan pergeseran tetap dan Vigenère dengan kunci berulang</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a>
      <span>›</span>
      <span>Caesar & Vigenere</span>
    </div>
  </div>
</div>

<div class="container section">
  <div class="two-col">

    <!-- FORM KIRI -->
    <div>
      <div class="card">
        <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 20px; color: var(--text-dark);">
          ✏️ Input & Pengaturan
        </h2>

        <form method="POST" action="" id="cipherForm">

          <?php if ($error): ?>
          <div class="alert alert-danger">⚠️ <?= htmlspecialchars($error) ?></div>
          <?php endif; ?>

          <!-- ALGORITHM -->
          <div class="form-group">
            <label>Pilih Algoritma</label>
            <div class="radio-group">
              <div class="radio-option">
                <input type="radio" name="algo" id="algo_caesar" value="caesar"
                  <?= (($_POST['algo'] ?? 'caesar') === 'caesar') ? 'checked' : '' ?>
                  onchange="toggleAlgoForm()">
                <label for="algo_caesar">🏛️ Caesar Cipher</label>
              </div>
              <div class="radio-option">
                <input type="radio" name="algo" id="algo_vigenere" value="vigenere"
                  <?= (($_POST['algo'] ?? '') === 'vigenere') ? 'checked' : '' ?>
                  onchange="toggleAlgoForm()">
                <label for="algo_vigenere">🔡 Vigenère Cipher</label>
              </div>
            </div>
          </div>

          <!-- PLAINTEXT -->
          <div class="form-group">
            <label for="plaintext">📝 Teks Input</label>
            <textarea
              id="plaintext"
              name="plaintext"
              placeholder="Masukkan teks (hanya huruf A-Z yang diproses)..."
              rows="4"
            ><?= htmlspecialchars($_POST['plaintext'] ?? '') ?></textarea>
          </div>

          <!-- CAESAR KEY -->
          <div class="form-group" id="caesarKeyGroup" <?= (($_POST['algo'] ?? 'caesar') === 'vigenere') ? 'style="display:none"' : '' ?>>
            <label for="caesar_key">🔢 Kunci Caesar (Shift 0-25)</label>
            <input
              type="number"
              id="caesar_key"
              name="caesar_key"
              placeholder="Contoh: 3"
              min="0"
              max="25"
              value="<?= htmlspecialchars($_POST['caesar_key'] ?? '3') ?>"
            >
          </div>

          <!-- VIGENERE KEY -->
          <div class="form-group" id="vigenereKeyGroup" <?= (($_POST['algo'] ?? 'caesar') !== 'vigenere') ? 'style="display:none"' : '' ?>>
            <label for="vigenere_key">🔡 Kunci Vigenère (huruf A-Z)</label>
            <input
              type="text"
              id="vigenere_key"
              name="vigenere_key"
              placeholder="Contoh: SECRET"
              value="<?= htmlspecialchars($_POST['vigenere_key'] ?? 'KEY') ?>"
              style="text-transform: uppercase;"
            >
          </div>

          <!-- ACTION BUTTONS -->
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button type="submit" name="action" value="encrypt" class="btn btn-primary" style="flex: 1;">
              🔒 Enkripsi
            </button>
            <button type="submit" name="action" value="decrypt" class="btn btn-outline" style="flex: 1;">
              🔓 Dekripsi
            </button>
          </div>

        </form>
      </div>

      <!-- CAESAR WHEEL (live) -->
      <div class="card" style="margin-top: 20px;" id="caesarWheelCard">
        <h3 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 4px; color: var(--green-dark);">
          🔤 Tabel Pergeseran Caesar (Shift = <span id="shiftDisplay"><?= $_POST['caesar_key'] ?? 3 ?></span>)
        </h3>
        <p style="font-size: 0.78rem; color: var(--text-light); margin-bottom: 12px;">Baris atas: Plaintext · Baris bawah: Ciphertext</p>
        <div class="caesar-wheel" id="caesarWheel">
          <?php
          $shift = (int)($_POST['caesar_key'] ?? 3);
          $table = caesar_alphabet_table($shift);
          foreach ($table as $row): ?>
          <div class="caesar-pair">
            <div class="cp-orig"><?= $row['plain'] ?></div>
            <div class="cp-enc"><?= $row['cipher'] ?></div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>

    <!-- HASIL KANAN -->
    <div>
      <?php if ($result): ?>

      <div class="result-card">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 8px;">
          <h2 style="font-size: 1.1rem; font-weight: 700; color: var(--text-dark);">
            <?= $result['action'] === 'encrypt' ? '🔒 Hasil Enkripsi' : '🔓 Hasil Dekripsi' ?>
          </h2>
          <span class="result-badge badge-success">
            <?= $result['algo'] === 'caesar' ? '🏛️ Caesar Cipher' : '🔡 Vigenère Cipher' ?>
          </span>
        </div>

        <!-- INPUT/OUTPUT DISPLAY -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
          <div style="background: rgba(111,207,151,0.06); padding: 14px; border-radius: 12px; border: 1px solid var(--border);">
            <div style="font-size: 0.78rem; color: var(--text-light); margin-bottom: 6px;">
              <?= $result['action'] === 'encrypt' ? '📝 Plaintext' : '🔐 Ciphertext' ?>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--text-dark); word-break: break-all; font-size: 0.9rem;">
              <?= htmlspecialchars($result['input']) ?>
            </div>
          </div>
          <div style="background: linear-gradient(135deg, rgba(111,207,151,0.12), rgba(47,160,132,0.08)); padding: 14px; border-radius: 12px; border: 1.5px solid var(--green-light);">
            <div style="font-size: 0.78rem; color: var(--text-light); margin-bottom: 6px;">
              <?= $result['action'] === 'encrypt' ? '🔐 Ciphertext' : '📝 Plaintext' ?>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: var(--green-dark); word-break: break-all; font-size: 0.9rem;">
              <?= htmlspecialchars($result['output']) ?>
            </div>
          </div>
        </div>

        <!-- KEY INFO -->
        <div class="alert alert-info" style="font-size: 0.85rem; margin-bottom: 16px;">
          🗝️ <strong>Kunci <?= $result['algo'] === 'caesar' ? 'Caesar' : 'Vigenère' ?>:</strong>
          <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">
            <?= htmlspecialchars($result['key']) ?>
          </span>
          <?php if ($result['algo'] === 'caesar'): ?>
          — Setiap huruf digeser <?= $result['key'] ?> posisi
          <?php else: ?>
          — Kunci diulang mengikuti panjang teks
          <?php endif; ?>
        </div>

        <!-- STEPS TABLE -->
        <?php if (!empty($result['steps'])): ?>
        <h3 style="font-size: 0.9rem; font-weight: 700; margin-bottom: 10px; color: var(--text-dark);">
          📋 Langkah Proses
          <span style="font-size: 0.78rem; font-weight: 400; color: var(--text-light);">
            (<?= count(array_filter($result['steps'], fn($s) => $s['result'] !== $s['plain'] ?? $s['original'])) ?> huruf diproses)
          </span>
        </h3>
        <div style="overflow-x: auto; max-height: 300px; overflow-y: auto;">
          <table class="step-table">
            <thead>
              <tr>
                <?php if ($result['algo'] === 'caesar'): ?>
                <th>#</th><th>Char</th><th>Pos</th><th>Shift</th><th>Pos Baru</th><th>Hasil</th><th>Formula</th>
                <?php else: ?>
                <th>#</th><th>Teks</th><th>Key</th><th>P</th><th>K</th><th>C</th><th>Hasil</th><th>Formula</th>
                <?php endif; ?>
              </tr>
            </thead>
            <tbody>
              <?php foreach (array_slice($result['steps'], 0, 30) as $i => $step): ?>
              <tr>
                <td><?= $i + 1 ?></td>
                <?php if ($result['algo'] === 'caesar'): ?>
                <td style="font-weight: 700;"><?= htmlspecialchars($step['original']) ?></td>
                <td><?= $step['pos_orig'] ?></td>
                <td><?= $step['shift'] ?></td>
                <td><?= $step['pos_new'] ?></td>
                <td style="font-weight: 700; color: var(--green-mid);"><?= htmlspecialchars($step['result']) ?></td>
                <td style="font-size: 0.78rem;"><?= $step['formula'] ?></td>
                <?php else: ?>
                <td style="font-weight: 700;"><?= htmlspecialchars($step['plain']) ?></td>
                <td style="color: var(--green-mid);"><?= htmlspecialchars($step['key_char']) ?></td>
                <td><?= $step['p'] ?></td>
                <td><?= $step['k'] ?></td>
                <td><?= $step['c'] ?></td>
                <td style="font-weight: 700; color: var(--green-mid);"><?= htmlspecialchars($step['result']) ?></td>
                <td style="font-size: 0.78rem;"><?= $step['formula'] ?></td>
                <?php endif; ?>
              </tr>
              <?php endforeach; ?>
              <?php if (count($result['steps']) > 30): ?>
              <tr>
                <td colspan="8" style="text-align: center; color: var(--text-light); font-size: 0.8rem;">
                  ... <?= count($result['steps']) - 30 ?> karakter lainnya tidak ditampilkan ...
                </td>
              </tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>

        <!-- OUTPUT BOX -->
        <div style="margin-top: 16px;">
          <div class="output-wrapper">
            <div class="output-box" id="resultOutput">
<?php if ($result['algo'] === 'caesar'): ?>
<span class="comment">// === CAESAR CIPHER ===</span>
<span class="label">Mode      :</span> <span class="highlight"><?= strtoupper($result['action']) ?></span>
<span class="label">Shift     :</span> <span class="highlight"><?= $result['key'] ?></span>
<span class="label">Input     :</span> <span class="value"><?= htmlspecialchars($result['input']) ?></span>
<span class="label">Output    :</span> <span class="success"><?= htmlspecialchars($result['output']) ?></span>
<?php else: ?>
<span class="comment">// === VIGENÈRE CIPHER ===</span>
<span class="label">Mode      :</span> <span class="highlight"><?= strtoupper($result['action']) ?></span>
<span class="label">Key       :</span> <span class="highlight"><?= htmlspecialchars($result['key']) ?></span>
<span class="label">Input     :</span> <span class="value"><?= htmlspecialchars($result['input']) ?></span>
<span class="label">Output    :</span> <span class="success"><?= htmlspecialchars($result['output']) ?></span>
<?php endif; ?>
            </div>
            <button class="copy-btn" onclick="copyText('resultOutput', this)">📋 Copy</button>
          </div>
        </div>

      </div>

      <?php else: ?>

      <!-- PLACEHOLDER -->
      <div class="card" style="text-align: center; padding: 48px 28px; border: 2px dashed var(--border);">
        <div style="font-size: 4rem; margin-bottom: 16px;">🔄</div>
        <h3 style="font-size: 1rem; font-weight: 600; color: var(--text-light); margin-bottom: 8px;">
          Caesar & Vigenère Cipher Siap
        </h3>
        <p style="font-size: 0.875rem; color: var(--text-light); margin-bottom: 20px;">
          Isi teks dan pilih algoritma, lalu klik Enkripsi atau Dekripsi
        </p>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; background: rgba(47,160,132,0.06); padding: 14px; border-radius: 10px; text-align: left; color: var(--text-dark);">
          Caesar: <span style="color: var(--green-mid);">HELLO + 3 = KHOOR</span><br>
          Vigenère: <span style="color: var(--green-mid);">HELLO + KEY = RIJVS</span>
        </div>
      </div>

      <?php endif; ?>
    </div><!-- end kanan -->

  </div><!-- end two-col -->
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

function toggleAlgoForm() {
  var algo = document.querySelector('input[name="algo"]:checked').value;
  document.getElementById('caesarKeyGroup').style.display    = algo === 'caesar'   ? '' : 'none';
  document.getElementById('vigenereKeyGroup').style.display  = algo === 'vigenere' ? '' : 'none';
  document.getElementById('caesarWheelCard').style.display   = algo === 'caesar'   ? '' : 'none';
}

// Update Caesar wheel on shift change
document.getElementById('caesar_key').addEventListener('input', function() {
  var shift = parseInt(this.value) || 0;
  shift = ((shift % 26) + 26) % 26;
  document.getElementById('shiftDisplay').textContent = shift;
  updateCaesarWheel(shift);
});

function updateCaesarWheel(shift) {
  var wheel = document.getElementById('caesarWheel');
  var html = '';
  for (var i = 0; i < 26; i++) {
    var orig = String.fromCharCode(65 + i);
    var enc  = String.fromCharCode(65 + (i + shift) % 26);
    html += '<div class="caesar-pair">' +
            '<div class="cp-orig">' + orig + '</div>' +
            '<div class="cp-enc">'  + enc  + '</div>' +
            '</div>';
  }
  wheel.innerHTML = html;
}

function copyText(elementId, btn) {
  var text = document.getElementById(elementId).innerText.trim();
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = '✅ Copied!';
    setTimeout(function() { btn.textContent = '📋 Copy'; }, 2000);
  });
}
</script>
</body>
</html>