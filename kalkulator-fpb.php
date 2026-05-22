<?php
// kalkulator-fpb.php — Kalkulator FPB dengan Algoritma Euclidean

$result = null;
$error = null;
$steps = [];

/**
 * Fungsi FPB menggunakan Algoritma Euclidean
 * Mengumpulkan langkah-langkah proses untuk ditampilkan
 */
function fpb($a, $b) {
    global $steps;
    $steps = [];
    $original_a = $a;
    $original_b = $b;

    // Pastikan a >= b
    if ($a < $b) {
        [$a, $b] = [$b, $a];
    }

    while ($b != 0) {
        $remainder = $a % $b;
        $steps[] = [
            'a' => $a,
            'b' => $b,
            'remainder' => $remainder,
            'equation' => "$a mod $b = $remainder"
        ];
        $a = $b;
        $b = $remainder;
    }

    return $a;
}

// Proses form POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_a = trim($_POST['angka1'] ?? '');
    $input_b = trim($_POST['angka2'] ?? '');

    if ($input_a === '' || $input_b === '') {
        $error = 'Kedua input tidak boleh kosong!';
    } elseif (!is_numeric($input_a) || !is_numeric($input_b)) {
        $error = 'Input harus berupa angka bulat positif!';
    } elseif ((int)$input_a <= 0 || (int)$input_b <= 0) {
        $error = 'Angka harus lebih dari 0!';
    } else {
        $a = (int)$input_a;
        $b = (int)$input_b;
        $hasil_fpb = fpb($a, $b);
        $is_relatif_prima = ($hasil_fpb === 1);
        $result = [
            'a' => $a,
            'b' => $b,
            'fpb' => $hasil_fpb,
            'relatif_prima' => $is_relatif_prima
        ];
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kalkulator FPB - KriptoVall</title>
  <link rel="stylesheet" href="style.css">
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
    <li><a href="kalkulator-fpb.php" class="active">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="sha256-generator.php">#️⃣ SHA-256</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- PAGE HEADER -->
<div class="page-header">
  <div class="page-header-inner">
    <h1>🔢 Kalkulator FPB</h1>
    <p>Hitung Faktor Persekutuan Terbesar (Greatest Common Divisor) menggunakan Algoritma Euclidean</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a>
      <span>›</span>
      <span>Kalkulator FPB</span>
    </div>
  </div>
</div>

<div class="container section">
  <div class="two-col">

    <!-- FORM KIRI -->
    <div>
      <div class="card">
        <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 20px; color: var(--text-dark);">
          ✏️ Input Nilai
        </h2>

        <form method="POST" action="">

          <?php if ($error): ?>
          <div class="alert alert-danger">⚠️ <?= htmlspecialchars($error) ?></div>
          <?php endif; ?>

          <div class="form-group">
            <label for="angka1">Nilai A</label>
            <input
              type="number"
              id="angka1"
              name="angka1"
              placeholder="Contoh: 48"
              min="1"
              value="<?= htmlspecialchars($_POST['angka1'] ?? '') ?>"
            >
          </div>

          <div class="form-group">
            <label for="angka2">Nilai B</label>
            <input
              type="number"
              id="angka2"
              name="angka2"
              placeholder="Contoh: 18"
              min="1"
              value="<?= htmlspecialchars($_POST['angka2'] ?? '') ?>"
            >
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%;">
            🔍 Hitung FPB
          </button>

        </form>
      </div>

      <!-- INFO CARD -->
      <div class="card" style="margin-top: 20px;">
        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 12px; color: var(--green-dark);">
          📖 Algoritma Euclidean
        </h3>
        <p style="font-size: 0.85rem; color: var(--text-light); line-height: 1.7;">
          Algoritma Euclidean mencari FPB dengan cara membagi bilangan terbesar dengan bilangan terkecil,
          lalu sisa pembagian (remainder) digunakan sebagai pembagi baru. Proses diulang hingga sisa = 0.
          FPB adalah nilai terakhir sebelum sisa = 0.
        </p>
        <div class="output-box" style="margin-top: 12px;">
<span class="comment">// Pseudocode Euclidean</span>
<span class="label">function</span> <span class="value">fpb(a, b):</span>
  <span class="highlight">while</span> b ≠ 0:
    remainder = a <span class="highlight">mod</span> b
    a = b
    b = remainder
  <span class="success">return</span> a  <span class="comment">// FPB</span>
        </div>
      </div>
    </div>

    <!-- HASIL KANAN -->
    <div>
      <?php if ($result): ?>

      <!-- RESULT CARD -->
      <div class="result-card">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: gap;">
          <h2 style="font-size: 1.1rem; font-weight: 700; color: var(--text-dark);">📊 Hasil Perhitungan</h2>
          <?php if ($result['relatif_prima']): ?>
          <span class="result-badge badge-success">✅ Relatif Prima</span>
          <?php else: ?>
          <span class="result-badge badge-warning">❌ Tidak Relatif Prima</span>
          <?php endif; ?>
        </div>

        <!-- FPB RESULT -->
        <div style="text-align: center; padding: 24px; background: linear-gradient(135deg, rgba(111,207,151,0.1), rgba(47,160,132,0.08)); border-radius: 12px; margin-bottom: 20px;">
          <div style="font-size: 0.85rem; color: var(--text-light); margin-bottom: 8px;">FPB dari <?= $result['a'] ?> dan <?= $result['b'] ?></div>
          <div style="font-size: 3rem; font-weight: 700; color: var(--green-mid); font-family: 'JetBrains Mono', monospace; line-height: 1;">
            <?= $result['fpb'] ?>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-light); margin-top: 8px;">
            GCD(<?= $result['a'] ?>, <?= $result['b'] ?>) = <?= $result['fpb'] ?>
          </div>
        </div>

        <!-- STATUS -->
        <?php if ($result['relatif_prima']): ?>
        <div class="alert alert-success">
          ✅ <strong>Kedua angka RELATIF PRIMA</strong> — Tidak memiliki faktor persekutuan selain 1
        </div>
        <?php else: ?>
        <div class="alert alert-danger" style="background: rgba(255,193,7,0.1); border-color: #ffc107; color: #856404;">
          ⚠️ <strong>Kedua angka TIDAK RELATIF PRIMA</strong> — Memiliki faktor persekutuan = <?= $result['fpb'] ?>
        </div>
        <?php endif; ?>

        <!-- LANGKAH PROSES -->
        <?php if (!empty($steps)): ?>
        <h3 style="font-size: 0.9rem; font-weight: 700; margin: 20px 0 12px; color: var(--text-dark);">
          🔄 Langkah-Langkah Algoritma Euclidean
        </h3>
        <div style="overflow-x: auto;">
          <table class="step-table">
            <thead>
              <tr>
                <th>Langkah</th>
                <th>a</th>
                <th>b</th>
                <th>a mod b</th>
                <th>Persamaan</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($steps as $i => $step): ?>
              <tr>
                <td><?= $i + 1 ?></td>
                <td><?= $step['a'] ?></td>
                <td><?= $step['b'] ?></td>
                <td><?= $step['remainder'] ?></td>
                <td><?= $step['equation'] ?></td>
              </tr>
              <?php endforeach; ?>
              <tr>
                <td colspan="4" style="font-weight: 700; color: var(--green-dark);">🏁 FPB Ditemukan</td>
                <td style="font-weight: 700; color: var(--green-mid);">GCD = <?= $result['fpb'] ?></td>
              </tr>
            </tbody>
          </table>
        </div>
        <?php endif; ?>

        <!-- OUTPUT BOX -->
        <h3 style="font-size: 0.9rem; font-weight: 700; margin: 20px 0 12px; color: var(--text-dark);">
          💻 Output Proses
        </h3>
        <div class="output-box">
<span class="comment">// ========== KALKULATOR FPB ==========</span>
<span class="label">Input :</span> <span class="value">A = <?= $result['a'] ?>, B = <?= $result['b'] ?></span>

<span class="comment">// Langkah-langkah Euclidean:</span>
<?php foreach ($steps as $i => $step): ?>
<span class="highlight">Langkah <?= $i + 1 ?> :</span> <span class="value"><?= $step['equation'] ?></span>
<?php endforeach; ?>

<span class="success">✅ HASIL : FPB(<?= $result['a'] ?>, <?= $result['b'] ?>) = <?= $result['fpb'] ?></span>
<span class="<?= $result['relatif_prima'] ? 'success' : 'error' ?>">
<?= $result['relatif_prima'] ? '🟢 RELATIF PRIMA' : '🔴 TIDAK RELATIF PRIMA' ?></span>
        </div>

      </div>

      <?php else: ?>

      <!-- PLACEHOLDER -->
      <div class="card" style="text-align: center; padding: 48px 28px; border: 2px dashed var(--border);">
        <div style="font-size: 4rem; margin-bottom: 16px;">🔢</div>
        <h3 style="font-size: 1rem; font-weight: 600; color: var(--text-light); margin-bottom: 8px;">Masukkan Dua Angka</h3>
        <p style="font-size: 0.875rem; color: var(--text-light);">
          Isi form di sebelah kiri untuk menghitung FPB menggunakan Algoritma Euclidean
        </p>
        <div style="margin-top: 20px;">
          <div style="font-size: 0.8rem; color: var(--text-light);">Contoh:</div>
          <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--green-mid); margin-top: 6px;">
            FPB(48, 18) = 6
          </div>
        </div>
      </div>

      <?php endif; ?>
    </div>

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
</script>
</body>
</html>