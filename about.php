<?php
// about.php — Halaman informasi tentang algoritma kriptografi
$current_page = 'about';
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>About - KriptoVall</title>
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
    <li><a href="kalkulator-fpb.php">🔢 Kalkulator FPB</a></li>
    <li><a href="simulasi-rsa.php">🔑 Simulasi RSA</a></li>
    <li><a href="xor-cipher.php">⊕ XOR Cipher</a></li>
    <li><a href="caesar-vigenere.php">🔄 Caesar & Vigenere</a></li>
    <li><a href="verifikator-dokumen.php">📋 Verifikator</a></li>
    <li><a href="ssl-generator.php">🛡️ SSL Generator</a></li>
    <li><a href="sha256-generator.php">#️⃣ SHA-256</a></li>
    <li><a href="about.php" class="active">ℹ️ About</a></li>
  </ul>
  <button class="hamburger" onclick="toggleNav()">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- PAGE HEADER -->
<div class="page-header">
  <div class="page-header-inner">
    <h1>📚 Tentang Algoritma</h1>
    <p>Penjelasan lengkap tentang algoritma kriptografi dan matematika diskrit yang digunakan dalam platform ini</p>
    <div class="breadcrumb">
      <a href="index.php">Home</a>
      <span>›</span>
      <span>About</span>
    </div>
  </div>
</div>

<div class="container section">

  <div style="margin-bottom: 32px;">
    <h2 class="section-title">🔐 Kriptografi</h2>
    <p class="section-subtitle">Ilmu dan seni melindungi informasi dengan mengubahnya ke bentuk yang tidak dapat dibaca</p>
  </div>

  <div class="about-grid">
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">👤</div>
        <h3>Rivaldi</h3>
      </div>
      <p>
        <strong>Rivaldi</strong> (NIM: 231220056) Mahasiswa Teknik Informatika Semster 6, Universitas Muhammadiyah Pontianak. Membuat website ini untuk memenuhi tugas kuliah Matakuliah Kriptografi Kelas 33.  
      </p>
      <hr class="divider" style="margin: 16px 0;">
    </div>
    <!-- KRIPTOGRAFI -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🔒</div>
        <h3>Kriptografi</h3>
      </div>
      <p>
        <strong>Kriptografi</strong> adalah ilmu dan seni untuk menjaga kerahasiaan pesan atau informasi dengan menggunakan teknik matematika.
        Tujuannya adalah memastikan hanya pihak yang berwenang yang dapat membaca pesan.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <p>Terdapat dua jenis utama:</p>
      <ul style="margin-top: 8px; padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li><strong>Simetris</strong> — kunci enkripsi = kunci dekripsi (XOR, Caesar)</li>
        <li><strong>Asimetris</strong> — kunci public & private terpisah (RSA)</li>
      </ul>
    </div>

    <!-- EUCLIDEAN -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🔢</div>
        <h3>Algoritma Euclidean</h3>
      </div>
      <p>
        <strong>Algoritma Euclidean</strong> adalah metode efisien untuk mencari Faktor Persekutuan Terbesar (FPB/GCD) dari dua bilangan bulat.
        Ditemukan oleh matematikawan Yunani kuno, Euclid (~300 SM).
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; background: rgba(31,111,95,0.05); padding: 12px; border-radius: 8px; color: var(--text-dark);">
        GCD(a, b) = GCD(b, a mod b)<br>
        GCD(a, 0) = a
      </div>
      <p style="margin-top: 12px; font-size: 0.85rem; color: var(--text-light);">
        Algoritma ini menjadi fondasi dalam kriptografi modern, terutama RSA.
      </p>
    </div>

    <!-- RSA -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🔑</div>
        <h3>RSA Encryption</h3>
      </div>
      <p>
        <strong>RSA</strong> (Rivest–Shamir–Adleman) adalah algoritma enkripsi asimetris yang dikembangkan tahun 1977.
        Keamanannya bergantung pada sulitnya memfaktorkan bilangan bulat besar.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <ul style="padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li>Public Key: dapat dibagikan ke siapa saja</li>
        <li>Private Key: rahasia, hanya pemilik yang tahu</li>
        <li>Enkripsi: menggunakan public key</li>
        <li>Dekripsi: menggunakan private key</li>
      </ul>
    </div>

    <!-- XOR CIPHER -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">⊕</div>
        <h3>XOR Cipher</h3>
      </div>
      <p>
        <strong>XOR Cipher</strong> adalah teknik enkripsi sederhana menggunakan operasi bitwise XOR (exclusive OR).
        Setiap bit plaintext di-XOR dengan bit kunci yang berulang.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; background: rgba(31,111,95,0.05); padding: 12px; border-radius: 8px; color: var(--text-dark);">
        0 XOR 0 = 0 &nbsp; 0 XOR 1 = 1<br>
        1 XOR 0 = 1 &nbsp; 1 XOR 1 = 0<br><br>
        Enkripsi: C = P ⊕ K<br>
        Dekripsi: P = C ⊕ K
      </div>
    </div>

    <!-- CAESAR CIPHER -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🏛️</div>
        <h3>Caesar Cipher</h3>
      </div>
      <p>
        <strong>Caesar Cipher</strong> adalah salah satu teknik enkripsi paling sederhana dan tertua.
        Dinamai dari Julius Caesar yang menggunakannya dalam komunikasi militer.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <p style="font-size: 0.85rem; color: var(--text-light);">
        Setiap huruf dalam teks digeser sebanyak <em>n</em> posisi dalam alfabet:
      </p>
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; background: rgba(31,111,95,0.05); padding: 12px; border-radius: 8px; color: var(--text-dark); margin-top: 8px;">
        A + 3 = D &nbsp;&nbsp; B + 3 = E<br>
        Z + 3 = C &nbsp;&nbsp; (wrap around)
      </div>
    </div>

    <!-- VIGENERE CIPHER -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🔡</div>
        <h3>Vigenère Cipher</h3>
      </div>
      <p>
        <strong>Vigenère Cipher</strong> adalah perluasan Caesar Cipher yang menggunakan kata kunci berulang.
        Setiap huruf plaintext digeser berdasarkan huruf kunci yang bersesuaian.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; background: rgba(31,111,95,0.05); padding: 12px; border-radius: 8px; color: var(--text-dark);">
        Plaintext: HELLO<br>
        Key:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; KEYKE<br>
        Cipher:&nbsp;&nbsp;&nbsp; RIJVS<br><br>
        E(Pi) = (Pi + Ki) mod 26
      </div>
    </div>

    <!-- DIGITAL SIGNATURE -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">✍️</div>
        <h3>Tanda Tangan Digital</h3>
      </div>
      <p>
        <strong>Digital Signature</strong> adalah mekanisme kriptografi yang memungkinkan verifikasi keaslian dan integritas dokumen digital.
        Menggunakan pasangan kunci public-private (seperti RSA).
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <ul style="padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li>Pengirim menandatangani dengan private key</li>
        <li>Penerima verifikasi dengan public key</li>
        <li>Jika dokumen diubah → verifikasi gagal</li>
      </ul>
    </div>

    <!-- MAN IN THE MIDDLE -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🕵️</div>
        <h3>Man in The Middle Attack</h3>
      </div>
      <p>
        <strong>MITM Attack</strong> adalah serangan di mana penyerang menyadap dan berpotensi memodifikasi komunikasi antara dua pihak.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <p style="font-size: 0.875rem; color: var(--text-light);">
        Digital Signature dapat mendeteksi serangan ini karena perubahan sekecil apapun pada dokumen akan menghasilkan hash yang berbeda,
        sehingga verifikasi tanda tangan akan <strong style="color: #dc3545;">GAGAL</strong>.
      </p>
    </div>

        <!-- SHA-256 -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">#️⃣</div>
        <h3>SHA-256 Hash</h3>
      </div>
      <p>
        <strong>SHA-256</strong> (Secure Hash Algorithm 256-bit) adalah fungsi hash kriptografi dari keluarga SHA-2.
        Menghasilkan <em>digest</em> 256-bit yang unik dan deterministic dari input apapun.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <ul style="padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li>Output selalu 256 bit (64 hex char)</li>
        <li>One-way — tidak bisa di-reverse</li>
        <li>Avalanche: 1 bit berubah → ~50% hash berubah</li>
        <li>Digunakan di SSL/TLS, Bitcoin, verifikasi file</li>
      </ul>
    </div>

    <!-- SSL/X.509 -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">🛡️</div>
        <h3>SSL & Sertifikat X.509</h3>
      </div>
      <p>
        <strong>SSL/TLS Certificate</strong> adalah dokumen digital yang membuktikan identitas server/domain.
        Format <em>X.509</em> menyimpan Public Key dan data identitas (DN) yang ditandatangani oleh CA.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <ul style="padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li>CSR — Certificate Signing Request</li>
        <li>CRT — Certificate (format PEM/DER)</li>
        <li>Self-signed — ditandatangani sendiri (testing)</li>
        <li>CA-signed — ditandatangani Certificate Authority</li>
      </ul>
    </div>

    <!-- PLATFORM INFO -->
    <div class="about-card">
      <div class="about-card-header">
        <div class="about-card-icon">💻</div>
        <h3>Tentang Platform Ini</h3>
      </div>
      <p>
        Platform ini dibangun sebagai media pembelajaran interaktif untuk memahami konsep kriptografi dan matematika diskrit melalui simulasi langsung.
      </p>
      <hr class="divider" style="margin: 16px 0;">
      <ul style="padding-left: 20px; font-size: 0.875rem; color: var(--text-light); line-height: 2;">
        <li>🐘 PHP Native (no framework)</li>
        <li>🎨 HTML5 + CSS3 Modern</li>
        <li>⚡ Vanilla JavaScript</li>
        <li>🔒 OpenSSL Extension</li>
        <li>📱 Responsive Design</li>
      </ul>
    </div>

  </div><!-- end about-grid -->

  <!-- REFERENSI -->
  <div style="margin-top: 48px;">
    <h2 class="section-title">📖 Referensi</h2>
    <div class="card" style="max-width: 600px;">
      <ul style="list-style: none; display: flex; flex-direction: column; gap: 12px;">
        <li style="display: flex; gap: 12px; font-size: 0.875rem; align-items: flex-start;">
          <span style="font-size: 1.2rem;">📘</span>
          <span><strong>Introduction to Modern Cryptography</strong> — Jonathan Katz & Yehuda Lindell</span>
        </li>
        <li style="display: flex; gap: 12px; font-size: 0.875rem; align-items: flex-start;">
          <span style="font-size: 1.2rem;">📗</span>
          <span><strong>Cryptography and Network Security</strong> — William Stallings</span>
        </li>
        <li style="display: flex; gap: 12px; font-size: 0.875rem; align-items: flex-start;">
          <span style="font-size: 1.2rem;">📙</span>
          <span><strong>Discrete Mathematics and Its Applications</strong> — Kenneth H. Rosen</span>
        </li>
        <li style="display: flex; gap: 12px; font-size: 0.875rem; align-items: flex-start;">
          <span style="font-size: 1.2rem;">🌐</span>
          <span><strong>OpenSSL Documentation</strong> — php.net/manual/en/book.openssl.php</span>
        </li>
      </ul>
    </div>
  </div>

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