#!/bin/bash

# ============================================
# TERMINAL KEEP - INSTALLER ANDROID
# Google Keep-like app untuk Android
# ============================================

# Warna untuk tampilan
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    clear
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              TERMINAL KEEP - INSTALLER ANDROID              ║"
    echo "║              Google Keep di Android                         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}➜ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Cek apakah di Termux
check_termux() {
    print_step "Mengecek environment..."
    
    if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
        print_success "Termux terdeteksi"
        return 0
    else
        print_error "Ini bukan Termux!"
        echo ""
        echo "Cara install Termux:"
        echo "1. Buka F-Droid: https://f-droid.org/"
        echo "2. Cari 'Termux'"
        echo "3. Install Termux"
        echo "4. Jalankan script ini DI DALAM Termux"
        echo ""
        echo "Atau download langsung:"
        echo "https://f-droid.org/repo/com.termux_118.apk"
        exit 1
    fi
}

# Minta izin storage
request_storage_permission() {
    print_step "Minta izin akses storage..."
    
    if [ -f "/system/bin/sh" ]; then
        # Android 11+
        termux-setup-storage
        sleep 2
        print_success "Izin storage diberikan"
    else
        print_info "Pastikan Termux sudah diizinkan akses storage"
    fi
}

# Update dan install packages
install_packages() {
    print_step "Update packages..."
    pkg update -y && pkg upgrade -y
    
    print_step "Install packages diperlukan..."
    pkg install -y python python-pip git nano wget
    
    print_success "Packages terinstall"
}

# Install Python libraries
install_python_libs() {
    print_step "Install Python libraries..."
    
    pip install cryptography bcrypt colorama
    
    print_success "Python libraries terinstall"
}

# Buat direktori aplikasi
create_app_dirs() {
    print_step "Membuat direktori aplikasi..."
    
    # Di internal storage
    mkdir -p /sdcard/TerminalKeep/data
    mkdir -p /sdcard/TerminalKeep/backup
    
    # Di Termux home
    mkdir -p ~/.terminal-keep
    mkdir -p ~/.terminal-keep/icons
    
    print_success "Direktori siap"
}

# Download icon dari internet
download_icons() {
    print_step "Mendownload icon aplikasi..."
    
    cd ~/.terminal-keep/icons
    
    # Download icon dari GitHub (icon notepad sederhana)
    # Menggunakan curl karena wget mungkin belum ada
    curl -s -o icon.png "https://raw.githubusercontent.com/google/material-design-icons/master/png/editor/sticky_note2/materialicons/24dp/2x/baseline_sticky_note2_black_24dp.png" 2>/dev/null || {
        # Fallback: buat icon teks
        echo "TK" > icon.txt
    }
    
    # Buat berbagai ukuran (gunakan Python)
    cat > ~/.terminal-keep/resize_icons.py << 'EOF'
from PIL import Image
import os

# Ukuran yang diinginkan
sizes = [16, 32, 48, 64, 72, 96, 128, 144, 152, 192, 256, 384, 512]

try:
    # Coba buka icon
    img = Image.open('icons/icon.png')
    
    # Resize untuk berbagai ukuran
    for size in sizes:
        resized = img.resize((size, size), Image.LANCZOS)
        resized.save(f'icons/icon_{size}.png')
        
    print("Icon berhasil diresize")
except:
    # Buat icon baru jika gagal
    for size in sizes:
        img = Image.new('RGB', (size, size), color=(66, 133, 244))
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        
        # Gambar kotak putih
        margin = size // 4
        draw.rectangle([margin, margin, size-margin, size-margin], fill=(255, 255, 255))
        
        # Gambar garis
        line_spacing = size // 8
        for i in range(3):
            y = margin + (i+1) * line_spacing
            draw.line([margin+5, y, size-margin-5, y], fill=(66, 133, 244), width=2)
        
        img.save(f'icons/icon_{size}.png')
    
    print("Icon baru dibuat")
EOF
    
    # Install PIL jika perlu
    pip install pillow 2>/dev/null
    
    # Jalankan script resize
    cd ~/.terminal-keep
    python resize_icons.py
    
    print_success "Icon siap"
}

# Buat aplikasi utama
create_main_app() {
    print_step "Membuat aplikasi utama..."
    
    cd ~/.terminal-keep
    
    # Buat file main.py
    cat > main.py << 'EOF'
#!/usr/bin/env python3
"""
TERMINAL KEEP - Aplikasi Catatan untuk Android
Google Keep-like di Termux
"""

import os
import sys
import sqlite3
import getpass
import base64
import json
from datetime import datetime
from pathlib import Path

# ==================== KEAMANAN ====================
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import bcrypt
except ImportError:
    os.system("pip install cryptography bcrypt")
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import bcrypt

# ==================== KONFIGURASI ANDROID ====================
ANDROID_STORAGE = "/sdcard/TerminalKeep"
DATA_DIR = Path(ANDROID_STORAGE) / "data"
BACKUP_DIR = Path(ANDROID_STORAGE) / "backup"

# Buat direktori jika belum ada
DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# ==================== WARNA ====================
class Warna:
    HEADER = '\033[95m'
    BIRU = '\033[94m'
    HIJAU = '\033[92m'
    KUNING = '\033[93m'
    MERAH = '\033[91m'
    PUTIH = '\033[97m'
    UNGU = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    CATATAN = {
        'putih': PUTIH,
        'merah': MERAH,
        'hijau': HIJAU,
        'kuning': KUNING,
        'biru': BIRU,
        'ungu': UNGU,
        'cyan': CYAN,
    }

# ==================== KEAMANAN ====================
class Keamanan:
    def __init__(self):
        self.salt = None
        self.key = None
        self.fernet = None
    
    def buat_salt(self):
        return os.urandom(16)
    
    def buat_kunci(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    def cek_password(self, password, hashed):
        return bcrypt.checkpw(password.encode(), hashed)
    
    def enkrip(self, teks):
        if not self.fernet:
            raise Exception("Keamanan belum diinisialisasi")
        return self.fernet.encrypt(teks.encode())
    
    def dekrip(self, teks_enkrip):
        if not self.fernet:
            raise Exception("Keamanan belum diinisialisasi")
        return self.fernet.decrypt(teks_enkrip).decode()
    
    def init_user(self, password, salt=None):
        if salt:
            self.salt = salt
        else:
            self.salt = self.buat_salt()
        self.key = self.buat_kunci(password, self.salt)
        self.fernet = Fernet(self.key)
        return self.salt

# ==================== DATABASE ====================
class Database:
    def __init__(self):
        self.db_path = DATA_DIR / 'catatan.db'
        self.conn = None
        self.keamanan = Keamanan()
        self.user_aktif = None
    
    def connect(self):
        self.conn = sqlite3.connect(str(self.db_path))
        self.buat_tabel()
    
    def disconnect(self):
        if self.conn:
            self.conn.close()
    
    def buat_tabel(self):
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                dibuat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS catatan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                judul TEXT NOT NULL,
                isi BLOB NOT NULL,
                warna TEXT DEFAULT 'putih',
                dipin BOOLEAN DEFAULT 0,
                diarsip BOOLEAN DEFAULT 0,
                dibuat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                diupdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        self.conn.commit()
    
    def daftar(self, username, password):
        try:
            cursor = self.conn.cursor()
            salt = self.keamanan.buat_salt()
            password_hash = self.keamanan.hash_password(password)
            
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, password_hash, salt)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def login(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT id, password_hash, salt FROM users WHERE username = ?',
            (username,)
        )
        result = cursor.fetchone()
        
        if result:
            user_id, password_hash, salt = result
            if self.keamanan.cek_password(password, password_hash):
                self.user_aktif = {
                    'id': user_id,
                    'username': username
                }
                self.keamanan.init_user(password, salt)
                return True
        return False
    
    def tambah_catatan(self, judul, isi, warna='putih'):
        if not self.user_aktif:
            return None
        
        isi_enkrip = self.keamanan.enkrip(isi)
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO catatan (user_id, judul, isi, warna)
            VALUES (?, ?, ?, ?)
        ''', (self.user_aktif['id'], judul, isi_enkrip, warna))
        self.conn.commit()
        return cursor.lastrowid
    
    def ambil_catatan(self, include_arsip=False):
        if not self.user_aktif:
            return []
        
        cursor = self.conn.cursor()
        
        if include_arsip:
            query = 'SELECT * FROM catatan WHERE user_id = ? ORDER BY dipin DESC, diupdate DESC'
        else:
            query = 'SELECT * FROM catatan WHERE user_id = ? AND diarsip = 0 ORDER BY dipin DESC, diupdate DESC'
        
        cursor.execute(query, (self.user_aktif['id'],))
        catatan = cursor.fetchall()
        
        hasil = []
        for catat in catatan:
            catat_list = list(catat)
            try:
                catat_list[3] = self.keamanan.dekrip(catat_list[3])
            except:
                catat_list[3] = "[Gagal didekrip]"
            hasil.append(tuple(catat_list))
        
        return hasil
    
    def update_catatan(self, catatan_id, judul=None, isi=None, warna=None, dipin=None):
        if not self.user_aktif:
            return False
        
        updates = []
        params = []
        
        if judul:
            updates.append("judul = ?")
            params.append(judul)
        
        if isi:
            isi_enkrip = self.keamanan.enkrip(isi)
            updates.append("isi = ?")
            params.append(isi_enkrip)
        
        if warna:
            updates.append("warna = ?")
            params.append(warna)
        
        if dipin is not None:
            updates.append("dipin = ?")
            params.append(1 if dipin else 0)
        
        updates.append("diupdate = CURRENT_TIMESTAMP")
        
        if not updates:
            return False
        
        query = f"UPDATE catatan SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
        params.extend([catatan_id, self.user_aktif['id']])
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor.rowcount > 0
    
    def arsip_catatan(self, catatan_id, arsip=True):
        if not self.user_aktif:
            return False
        
        cursor = self.conn.cursor()
        cursor.execute(
            'UPDATE catatan SET diarsip = ?, diupdate = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
            (1 if arsip else 0, catatan_id, self.user_aktif['id'])
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def hapus_catatan(self, catatan_id):
        if not self.user_aktif:
            return False
        
        cursor = self.conn.cursor()
        cursor.execute(
            'DELETE FROM catatan WHERE id = ? AND user_id = ?',
            (catatan_id, self.user_aktif['id'])
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def cari_catatan(self, query):
        if not self.user_aktif:
            return []
        
        semua = self.ambil_catatan(include_arsip=True)
        hasil = []
        for catat in semua:
            if query.lower() in catat[2].lower() or query.lower() in catat[3].lower():
                hasil.append(catat)
        return hasil
    
    # Fitur backup untuk Android
    def backup_ke_sd(self):
        if not self.user_aktif:
            return False
        
        import shutil
        from datetime import datetime
        
        # Buat nama file backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = BACKUP_DIR / f"backup_{self.user_aktif['username']}_{timestamp}.db"
        
        # Copy database
        shutil.copy2(self.db_path, backup_file)
        
        return str(backup_file)
    
    def restore_dari_sd(self, file_backup):
        if not os.path.exists(file_backup):
            return False
        
        import shutil
        
        # Restore database
        shutil.copy2(file_backup, self.db_path)
        
        return True

# ==================== TAMPILAN ====================
def bersih_layar():
    os.system('clear')

def tampil_header(judul):
    print(f"\n{Warna.HEADER}{Warna.BOLD}╔{'═'*50}╗")
    print(f"║{judul:^50}║")
    print(f"╚{'═'*50}╝{Warna.RESET}\n")

def tampil_catatan(catatan, tampil_id=True):
    id, user_id, judul, isi, warna, dipin, diarsip, dibuat, diupdate = catatan
    
    warna_code = Warna.CATATAN.get(warna, Warna.PUTIH)
    pin = "📌 " if dipin else ""
    arsip = "📦 " if diarsip else ""
    
    print(f"\n{warna_code}{'─'*50}")
    if tampil_id:
        print(f"ID: {id}")
    print(f"{pin}{arsip}{judul}")
    print(f"{warna_code}{'─'*50}")
    print(f"{isi}")
    print(f"{warna_code}Dibuat: {dibuat}")
    if diupdate != dibuat:
        print(f"Diupdate: {diupdate}")
    print(f"{warna_code}{'─'*50}{Warna.RESET}")

def input_user(prompt, boleh_kosong=False):
    while True:
        if sys.version_info >= (3, 0):
            nilai = input(prompt).strip()
        else:
            nilai = raw_input(prompt).strip()
        
        if nilai or boleh_kosong:
            return nilai
        print(f"{Warna.MERAH}Input tidak boleh kosong{Warna.RESET}")

def konfirmasi(prompt):
    respon = input(f"{prompt} (y/N): ").strip().lower()
    return respon == 'y'

# ==================== APLIKASI UTAMA ====================
class TerminalKeep:
    def __init__(self):
        self.db = Database()
        self.running = True
    
    def mulai(self):
        self.db.connect()
        
        bersih_layar()
        print(f"{Warna.HIJAU}{Warna.BOLD}")
        print("╔════════════════════════════════════════════════╗")
        print("║         TERMINAL KEEP FOR ANDROID              ║")
        print("║         Aplikasi Catatan Pribadi mu            ║")
        print("╚════════════════════════════════════════════════╝")
        print(f"{Warna.RESET}")
        print(f"{Warna.CYAN}Data tersimpan di: /sdcard/TerminalKeep/{Warna.RESET}")
        
        while True:
            print(f"\n{Warna.BIRU}1.{Warna.RESET} Login")
            print(f"{Warna.BIRU}2.{Warna.RESET} Daftar Baru")
            print(f"{Warna.BIRU}3.{Warna.RESET} Keluar")
            
            pilihan = input_user("Pilih (1-3): ")
            
            if pilihan == '1':
                if self.login():
                    self.menu_utama()
            elif pilihan == '2':
                self.daftar()
            elif pilihan == '3':
                self.selesai()
                return
            else:
                print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}")
    
    def login(self):
        print(f"\n{Warna.HEADER}=== LOGIN ==={Warna.RESET}")
        username = input_user("Username: ")
        password = getpass.getpass("Password: ")
        
        if self.db.login(username, password):
            print(f"{Warna.HIJAU}✓ Selamat datang, {username}!{Warna.RESET}")
            return True
        else:
            print(f"{Warna.MERAH}✗ Username atau password salah{Warna.RESET}")
            input("\nTekan Enter untuk lanjut...")
            return False
    
    def daftar(self):
        print(f"\n{Warna.HEADER}=== DAFTAR AKUN BARU ==={Warna.RESET}")
        username = input_user("Username: ")
        
        while True:
            password = getpass.getpass("Password (min 6 karakter): ")
            if len(password) < 6:
                print(f"{Warna.MERAH}Password minimal 6 karakter{Warna.RESET}")
                continue
            
            confirm = getpass.getpass("Ulangi password: ")
            if password == confirm:
                break
            print(f"{Warna.MERAH}Password tidak cocok{Warna.RESET}")
        
        if self.db.daftar(username, password):
            print(f"{Warna.HIJAU}✓ Akun berhasil dibuat! Silakan login.{Warna.RESET}")
        else:
            print(f"{Warna.MERAH}✗ Username sudah digunakan{Warna.RESET}")
        
        input("\nTekan Enter untuk lanjut...")
    
    def menu_utama(self):
        while self.running:
            bersih_layar()
            tampil_header(f"TERMINAL KEEP - {self.db.user_aktif['username']}")
            print(f"{Warna.BIRU}1.{Warna.RESET} 📝 Lihat Catatan")
            print(f"{Warna.BIRU}2.{Warna.RESET} ➕ Buat Catatan Baru")
            print(f"{Warna.BIRU}3.{Warna.RESET} 🔍 Cari Catatan")
            print(f"{Warna.BIRU}4.{Warna.RESET} 📦 Arsip")
            print(f"{Warna.BIRU}5.{Warna.RESET} 💾 Backup ke SD Card")
            print(f"{Warna.BIRU}6.{Warna.RESET} 🔄 Restore dari SD Card")
            print(f"{Warna.BIRU}7.{Warna.RESET} 🚪 Logout")
            print(f"{Warna.BIRU}8.{Warna.RESET} ❌ Keluar")
            
            pilihan = input_user("Pilih (1-8): ")
            
            if pilihan == '1':
                self.lihat_catatan()
            elif pilihan == '2':
                self.buat_catatan()
            elif pilihan == '3':
                self.cari_catatan()
            elif pilihan == '4':
                self.lihat_arsip()
            elif pilihan == '5':
                self.backup_data()
            elif pilihan == '6':
                self.restore_data()
            elif pilihan == '7':
                self.db.user_aktif = None
                print(f"{Warna.KUNING}Logout berhasil{Warna.RESET}")
                input("\nTekan Enter untuk lanjut...")
                return
            elif pilihan == '8':
                if konfirmasi("Yakin mau keluar?"):
                    self.running = False
            else:
                print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}")
                input("Tekan Enter untuk lanjut...")
    
    def lihat_catatan(self):
        bersih_layar()
        tampil_header("CATATAN SAYA")
        
        catatan = self.db.ambil_catatan()
        
        if not catatan:
            print(f"{Warna.KUNING}Belum ada catatan. Buat catatan baru!{Warna.RESET}")
            input("\nTekan Enter untuk lanjut...")
            return
        
        for catat in catatan:
            tampil_catatan(catat)
        
        self.menu_aksi_catatan()
    
    def lihat_arsip(self):
        bersih_layar()
        tampil_header("ARSIP")
        
        catatan = self.db.ambil_catatan(include_arsip=True)
        catatan_arsip = [c for c in catatan if c[6]]
        
        if not catatan_arsip:
            print(f"{Warna.KUNING}Belum ada catatan di arsip{Warna.RESET}")
            input("\nTekan Enter untuk lanjut...")
            return
        
        for catat in catatan_arsip:
            tampil_catatan(catat)
        
        self.menu_aksi_catatan()
    
    def menu_aksi_catatan(self):
        print(f"\n{Warna.BIRU}=== AKSI ==={Warna.RESET}")
        print("1. ✏️  Edit")
        print("2. 📌 Pin/Unpin")
        print("3. 📦 Arsip/Unarsip")
        print("4. 🗑️  Hapus")
        print("5. ↩️  Kembali")
        
        pilihan = input_user("Pilih aksi (1-5): ")
        
        if pilihan == '1':
            self.edit_catatan()
        elif pilihan == '2':
            self.toggle_pin()
        elif pilihan == '3':
            self.toggle_arsip()
        elif pilihan == '4':
            self.hapus_catatan()
        elif pilihan == '5':
            return
        else:
            print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
    
    def buat_catatan(self):
        bersih_layar()
        tampil_header("BUAT CATATAN BARU")
        
        judul = input_user("Judul: ")
        print("Isi catatan (ketik '.' di baris baru untuk selesai):")
        
        baris = []
        while True:
            line = input()
            if line == '.':
                break
            baris.append(line)
        
        isi = '\n'.join(baris)
        
        print(f"\nWarna tersedia: putih, merah, hijau, kuning, biru, ungu, cyan")
        warna = input_user("Warna (default: putih): ").lower()
        if warna not in ['putih', 'merah', 'hijau', 'kuning', 'biru', 'ungu', 'cyan']:
            warna = 'putih'
        
        catatan_id = self.db.tambah_catatan(judul, isi, warna)
        print(f"{Warna.HIJAU}✓ Catatan berhasil dibuat! (ID: {catatan_id}){Warna.RESET}")
        input("\nTekan Enter untuk lanjut...")
    
    def edit_catatan(self):
        catatan_id = input_user("ID catatan yang mau diedit: ")
        
        try:
            catatan_id = int(catatan_id)
        except ValueError:
            print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
            return
        
        catatan = self.db.ambil_catatan(include_arsip=True)
        catatan_sekarang = None
        for catat in catatan:
            if catat[0] == catatan_id:
                catatan_sekarang = catat
                break
        
        if not catatan_sekarang:
            print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
            return
        
        print(f"\n{Kosongkan untuk mempertahankan nilai lama}")
        judul_baru = input_user(f"Judul [{catatan_sekarang[2]}]: ", boleh_kosong=True)
        if not judul_baru:
            judul_baru = catatan_sekarang[2]
        
        print(f"Isi lama:\n{catatan_sekarang[3]}")
        print("Isi baru (ketik '.' di baris baru untuk selesai, kosongkan jika tidak diubah):")
        
        baris = []
        while True:
            line = input()
            if line == '.':
                break
            baris.append(line)
        
        isi_baru = '\n'.join(baris) if baris else None
        
        if self.db.update_catatan(catatan_id, judul=judul_baru, isi=isi_baru):
            print(f"{Warna.HIJAU}✓ Catatan berhasil diupdate!{Warna.RESET}")
        else:
            print(f"{Warna.MERAH}✗ Gagal update catatan{Warna.RESET}")
        
        input("Tekan Enter untuk lanjut...")
    
    def toggle_pin(self):
        catatan_id = input_user("ID catatan: ")
        
        try:
            catatan_id = int(catatan_id)
        except ValueError:
            print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
            return
        
        catatan = self.db.ambil_catatan(include_arsip=True)
        for catat in catatan:
            if catat[0] == catatan_id:
                status_baru = not catat[5]
                if self.db.update_catatan(catatan_id, dipin=status_baru):
                    status = "di-pin" if status_baru else "di-unpin"
                    print(f"{Warna.HIJAU}✓ Catatan {status}{Warna.RESET}")
                else:
                    print(f"{Warna.MERAH}✗ Gagal update{Warna.RESET}")
                break
        else:
            print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}")
        
        input("Tekan Enter untuk lanjut...")
    
    def toggle_arsip(self):
        catatan_id = input_user("ID catatan: ")
        
        try:
            catatan_id = int(catatan_id)
        except ValueError:
            print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
            return
        
        catatan = self.db.ambil_catatan(include_arsip=True)
        for catat in catatan:
            if catat[0] == catatan_id:
                status_baru = not catat[6]
                if self.db.arsip_catatan(catatan_id, status_baru):
                    status = "di-arsip" if status_baru else "di-unarsip"
                    print(f"{Warna.HIJAU}✓ Catatan {status}{Warna.RESET}")
                else:
                    print(f"{Warna.MERAH}✗ Gagal update{Warna.RESET}")
                break
        else:
            print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}")
        
        input("Tekan Enter untuk lanjut...")
    
    def hapus_catatan(self):
        catatan_id = input_user("ID catatan yang mau dihapus: ")
        
        try:
            catatan_id = int(catatan_id)
        except ValueError:
            print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}")
            input("Tekan Enter untuk lanjut...")
            return
        
        if konfirmasi(f"Yakin mau hapus catatan #{catatan_id}?"):
            if self.db.hapus_catatan(catatan_id):
                print(f"{Warna.HIJAU}✓ Catatan dihapus{Warna.RESET}")
            else:
                print(f"{Warna.MERAH}✗ Gagal hapus{Warna.RESET}")
        else:
            print("Dibatalkan")
        
        input("Tekan Enter untuk lanjut...")
    
    def cari_catatan(self):
        bersih_layar()
        tampil_header("CARI CATATAN")
        
        query = input_user("Kata kunci: ")
        hasil = self.db.cari_catatan(query)
        
        if not hasil:
            print(f"{Warna.KUNING}Tidak ada catatan dengan kata '{query}'{Warna.RESET}")
        else:
            print(f"\nDitemukan {len(hasil)} catatan:")
            for catat in hasil:
                tampil_catatan(catat)
        
        input("\nTekan Enter untuk lanjut...")
    
    def backup_data(self):
        print(f"\n{Warna.HEADER}=== BACKUP KE SD CARD ==={Warna.RESET}")
        
        file_backup = self.db.backup_ke_sd()
        if file_backup:
            print(f"{Warna.HIJAU}✓ Backup berhasil!{Warna.RESET}")
            print(f"Lokasi: {file_backup}")
        else:
            print(f"{Warna.MERAH}✗ Backup gagal{Warna.RESET}")
        
        input("\nTekan Enter untuk lanjut...")
    
    def restore_data(self):
        print(f"\n{Warna.HEADER}=== RESTORE DARI SD CARD ==={Warna.RESET}")
        
        # List file backup
        backup_files = list(BACKUP_DIR.glob("*.db"))
        
        if not backup_files:
            print(f"{Warna.KUNING}Tidak ada file backup{Warna.RESET}")
            input("\nTekan Enter untuk lanjut...")
            return
        
        print("File backup tersedia:")
        for i, f in enumerate(backup_files, 1):
            print(f"{i}. {f.name}")
        
        pilihan = input_user("Pilih nomor backup (0 untuk batal): ")
        
        if pilihan == '0':
            return
        
        try:
            idx = int(pilihan) - 1
            if 0 <= idx < len(backup_files):
                if konfirmasi("Yakin mau restore? Data sekarang akan ditimpa!"):
                    if self.db.restore_dari_sd(backup_files[idx]):
                        print(f"{Warna.HIJAU}✓ Restore berhasil!{Warna.RESET}")
                    else:
                        print(f"{Warna.MERAH}✗ Restore gagal{Warna.RESET}")
            else:
                print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}")
        except:
            print(f"{Warna.MERAH}Input tidak valid{Warna.RESET}")
        
        input("\nTekan Enter untuk lanjut...")
    
    def selesai(self):
        self.db.disconnect()
        print(f"\n{Warna.HIJAU}Sampai jumpa! 👋{Warna.RESET}")

# ==================== MAIN ====================
if __name__ == "__main__":
    try:
        app = TerminalKeep()
        app.mulai()
    except KeyboardInterrupt:
        print(f"\n{Warna.KUNING}Dadah! 👋{Warna.RESET}")
    except Exception as e:
        print(f"{Warna.MERAH}Error: {e}{Warna.RESET}")
        input("Tekan Enter untuk keluar...")
EOF
    
    print_success "Aplikasi utama selesai"
}

# Buat script untuk menjalankan
create_launcher() {
    print_step "Membuat launcher..."
    
    cd ~/.terminal-keep
    
    # Buat script jalan
    cat > jalan.sh << 'EOF'
#!/bin/bash
cd ~/.terminal-keep
python main.py
EOF
    chmod +x jalan.sh
    
    # Buat shortcut di home
    cat > ~/terminal-keep << 'EOF'
#!/bin/bash
cd ~/.terminal-keep
python main.py
EOF
    chmod +x ~/terminal-keep
    
    print_success "Launcher siap"
}

# Buat widget untuk Android (via Termux:widget)
create_widget() {
    print_step "Membuat widget shortcut..."
    
    # Untuk Termux:widget
    mkdir -p ~/.shortcuts
    
    cat > ~/.shortcuts/TerminalKeep.sh << 'EOF'
#!/bin/bash
cd ~/.terminal-keep
python main.py
EOF
    chmod +x ~/.shortcuts/TerminalKeep.sh
    
    print_success "Widget siap (butuh Termux:Widget dari F-Droid)"
}

# Buat uninstaller
create_uninstaller() {
    cat > ~/.terminal-keep/uninstall.sh << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Menghapus Terminal Keep..."

# Hapus aplikasi
rm -rf ~/.terminal-keep
rm -f ~/terminal-keep

# Hapus data (opsional)
read -p "Hapus juga semua catatan? (y/N): " hapus_data
if [[ "$hapus_data" == "y" ]] || [[ "$hapus_data" == "Y" ]]; then
    rm -rf /sdcard/TerminalKeep
    echo -e "${GREEN}✓ Data dihapus${NC}"
fi

# Hapus widget
rm -f ~/.shortcuts/TerminalKeep.sh

echo -e "${GREEN}✓ Terminal Keep telah dihapus${NC}"
EOF
    chmod +x ~/.terminal-keep/uninstall.sh
}

# Tampilkan instruksi
show_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
    echo "║         INSTALASI ANDROID SELESAI! 🎉                      ║"
    echo "╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}CARA MENGGUNAKAN DI ANDROID:${NC}"
    echo ""
    echo -e "${BLUE}1.${NC} Setiap kali mau pakai, ketik di Termux:"
    echo "   ~/terminal-keep"
    echo ""
    echo -e "${BLUE}2.${NC} ATAU buat widget di home screen:"
    echo "   - Install Termux:Widget dari F-Droid"
    echo "   - Tambah widget Terminal Keep di home screen"
    echo ""
    echo -e "${BLUE}3.${NC} ATAU langsung jalanin:"
    echo "   cd ~/.terminal-keep"
    echo "   python main.py"
    echo ""
    echo -e "${GREEN}FITUR ANDROID:${NC}"
    echo "   • Data tersimpan di SD Card: /sdcard/TerminalKeep/"
    echo "   • Backup otomatis ke SD Card"
    echo "   • Widget support (dengan Termux:Widget)"
    echo "   • Semua catatan dienkripsi"
    echo ""
    echo -e "${YELLOW}Untuk menghapus:${NC}"
    echo "   ~/.terminal-keep/uninstall.sh"
    echo ""
}

# ==================== MAIN ====================
main() {
    print_header
    
    # Cek Termux
    check_termux
    
    echo -e "${YELLOW}Installer akan:${NC}"
    echo "  ✓ Setup storage Android"
    echo "  ✓ Install packages (python, git, dll)"
    echo "  ✓ Download dan buat icon"
    echo "  ✓ Install aplikasi Terminal Keep"
    echo "  ✓ Buat shortcut dan widget"
    echo "  ✓ Data akan disimpan di SD Card"
    echo ""
    
    read -p "Tekan Enter untuk mulai instalasi (Ctrl+C batal)..."
    
    # Minta izin storage
    request_storage_permission
    
    # Install packages
    install_packages
    
    # Install Python libs
    install_python_libs
    
    # Buat direktori
    create_app_dirs
    
    # Download icons
    download_icons
    
    # Buat aplikasi
    create_main_app
    
    # Buat launcher
    create_launcher
    
    # Buat widget
    create_widget
    
    # Buat uninstaller
    create_uninstaller
    
    # Tampilkan instruksi
    show_instructions
}

# Jalankan main
main
