<?php
$host = "localhost"; $user_db = "root"; $pass_db = ""; $db_name = "keamana_db";
$conn = new mysqli($host, $user_db, $pass_db, $db_name);

$pesan = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_input = $_POST['username'];
    $pass_input = $_POST['password'];

    // ?? KODE RENTAN (VULNERABLE) - PENGGABUNGAN STRING LANGSUNG
    $sql = "SELECT * FROM users WHERE username = '$user_input' AND password = '$pass_input'";
    
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $pesan = "? Berhasil Login! Selamat datang, Role: " . $row['role'];
    } else {
        $pesan = "? Gagal Login! Cek kembali username/password.";
    }
        // 1. Siapkan cetakan Query dengan tanda tanya (?) sebagai tempat variabel
    $sql_aman = "SELECT * FROM users WHERE username = ? AND password = ?";
    
    // 2. Kirim kerangka query ke MySQL untuk di-prepare (dikunci strukturnya)
    $stmt = $conn->prepare($sql_aman);

    // 3. Binding Parameter: "ss" artinya dua inputan tersebut adalah String
    $stmt->bind_param("ss", $user_input, $pass_input);

    // 4. Eksekusi query dengan data aman yang baru disisipkan
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $pesan = "? Berhasil Login! Selamat datang, Role: " . $row['role'];
    } else {
        $pesan = "? Gagal Login! Sistem memblokir injeksi.";
    }
    
    $stmt->close();
}

?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistem Login Perusahaan</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-card {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        .login-card h2 {
            text-align: center;
            color: #333333;
            margin-bottom: 24px;
            font-size: 24px;
        }
        .alert {
            text-align: center;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .form-group {
            margin-bottom: 16px;
        }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: #555555;
            font-size: 14px;
        }
        .form-control {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #cccccc;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.2s;
        }
        .form-control:focus {
            outline: none;
            border-color: #007bff;
        }
        .btn-submit {
            width: 100%;
            padding: 12px;
            background-color: #007bff;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 10px;
        }
        .btn-submit:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>Sistem Login Perusahaan</h2>
        
        <?php if (!empty($pesan)): ?>
            <?php $is_success = strpos($pesan, 'Berhasil') !== false; ?>
            <div class="alert <?= $is_success ? 'alert-success' : 'alert-error' ?>">
                <?= $pesan; ?>
            </div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control" placeholder="Masukkan username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <!-- Menggunakan type text untuk memudahkan lab SQLi -->
                <input type="text" id="password" name="password" class="form-control" placeholder="Masukkan password" required>
            </div>
            
            <button type="submit" class="btn-submit">Masuk</button>
        </form>
    </div>
</body>
</html>