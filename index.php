<?php
// index.php - Halaman Utama Dashboard
$current_page = 'home';
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KriptoVall - Tugas-Tugas Kriptografi Rivaldi</title>
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
    <li><a href="index.php" class="active">🏠 Home</a></li>
    <li><a href="kalkulator-fpb.php">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="about.php">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()" id="hamburger" aria-label="Menu">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- HERO SECTION -->
<section class="hero">
  <div class="hero-content">
    <div class="hero-badge">✨ Platform Tugas Kriptografi</div>
    <h1>Kriptografi </h1>
    <p>Kumpulan Tugas - Tugas Kriptografi Rivaldi (231220056).</p>
    <div class="hero-stats">
      <div class="hero-stat">
        <span class="hero-stat-num">6</span>
        <div class="hero-stat-label">Algoritma</div>
      </div>
      <div class="hero-stat">
        <span class="hero-stat-num">100%</span>
        <div class="hero-stat-label">PHP Native</div>
      </div>
      <div class="hero-stat">
        <span class="hero-stat-num">∞</span>
        <div class="hero-stat-label">Simulasi</div>
      </div>
    </div>
  </div>
</section>

<!-- MENU CARDS -->
<div class="container section">
  <div style="margin-bottom: 32px;">
    <h2 class="section-title">🚀 Modul Pembelajaran</h2>
    <p class="section-subtitle">Pilih modul yang ingin Anda pelajari dan eksplorasi algoritmanya secara interaktif</p>
  </div>

  <div class="card-grid">

    <!-- FPB -->
    <a href="kalkulator-fpb.php" class="card card-menu">
      <div class="card-icon">🔢</div>
      <div>
        <div class="card-title">Kalkulator FPB</div>
        <div class="card-desc">Hitung Faktor Persekutuan Terbesar menggunakan Algoritma Euclidean dengan visualisasi langkah-per-langkah.</div>
      </div>
      <div class="card-arrow">Mulai Belajar →</div>
    </a>

    <!-- RSA -->
    <a href="simulasi-rsa.php" class="card card-menu">
      <div class="card-icon">🔑</div>
      <div>
        <div class="card-title">Simulasi RSA</div>
        <div class="card-desc">Simulasikan enkripsi asimetris RSA: generate key pair, enkripsi pesan dengan public key, dekripsi dengan private key.</div>
      </div>
      <div class="card-arrow">Mulai Simulasi →</div>
    </a>

    <!-- XOR -->
    <a href="xor-cipher.php" class="card card-menu">
      <div class="card-icon">⊕</div>
      <div>
        <div class="card-title">XOR Cipher</div>
        <div class="card-desc">Enkripsi dan dekripsi teks menggunakan operasi XOR bitwise dengan visualisasi binary dan output hexadecimal.</div>
      </div>
      <div class="card-arrow">Coba Sekarang →</div>
    </a>

    <!-- Caesar & Vigenere -->
    <a href="caesar-vigenere.php" class="card card-menu">
      <div class="card-icon">🔄</div>
      <div>
        <div class="card-title">Caesar & Vigenere</div>
        <div class="card-desc">Pelajari dua cipher klasik: Caesar Cipher dengan pergeseran tetap dan Vigenere Cipher dengan key yang berulang.</div>
      </div>
      <div class="card-arrow">Eksplorasi →</div>
    </a>

    <!-- Verifikator -->
    <a href="verifikator-dokumen.php" class="card card-menu">
      <div class="card-icon">📋</div>
      <div>
        <div class="card-title">Verifikator Dokumen</div>
        <div class="card-desc">Simulasi tanda tangan digital dan deteksi modifikasi dokumen menggunakan OpenSSL dan algoritma RSA.</div>
      </div>
      <div class="card-arrow">Verifikasi →</div>
    </a>

    <!-- SSL Generator -->
    <a href="ssl-generator.php" class="card card-menu">
      <div class="card-icon">🛡️</div>
      <div>
        <div class="card-title">SSL Certificate Generator</div>
        <div class="card-desc">Generate self-signed SSL certificates (CSR, Private Key, Public Key) untuk development dan testing purposes.</div>
      </div>
      <div class="card-arrow">Generate SSL →</div>
    </a>

    <!-- About -->
    <a href="about.php" class="card card-menu">
      <div class="card-icon">📚</div>
      <div>
        <div class="card-title">Tentang Algoritma</div>
        <div class="card-desc">Pelajari konsep dasar kriptografi: Euclidean, RSA, XOR, Caesar, Vigenere, dan tanda tangan digital.</div>
      </div>
      <div class="card-arrow">Pelajari →</div>
    </a>

  </div>
</div>

<!-- STATISTIK SECTION -->
<div style="background: var(--white); border-top: 1.5px solid var(--border); border-bottom: 1.5px solid var(--border); padding: 48px 0;">
  <div class="container">
    <h2 class="section-title" style="margin-bottom: 24px;">📊 Ringkasan Platform</h2>
    <div class="stat-row">
      <div class="stat-item">
        <span class="stat-item-num">6</span>
        <div class="stat-item-label">Algoritma Tersedia</div>
      </div>
      <div class="stat-item">
        <span class="stat-item-num">RSA</span>
        <div class="stat-item-label">Enkripsi Asimetris</div>
      </div>
      <div class="stat-item">
        <span class="stat-item-num">XOR</span>
        <div class="stat-item-label">Symmetric Cipher</div>
      </div>
      <div class="stat-item">
        <span class="stat-item-num">GCD</span>
        <div class="stat-item-label">Algoritma Euclidean</div>
      </div>
      <div class="stat-item">
        <span class="stat-item-num">SHA</span>
        <div class="stat-item-label">Digital Signature</div>
      </div>
      <div class="stat-item">
        <span class="stat-item-num">CSR</span>
        <div class="stat-item-label">Certificate Signing Request</div>
      </div>
    </div>

    <div class="alert alert-info" style="max-width: 600px;">
      <strong>FunFact:</strong> Web ini di develop oleh Rivaldi(VibeCoder) menggunakan AI dan PHP.
    </div>
  </div>
</div>

<!-- FOOTER -->
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