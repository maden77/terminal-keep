#!/bin/bash

# ============================================
# TERMINAL KEEP - ONE CLICK INSTALLER
# Google Keep-like app untuk terminal
# ============================================

# Warna untuk tampilan
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Fungsi untuk tampilan
print_header() {
    clear
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              TERMINAL KEEP - INSTALLER                      ║"
    echo "║              Google Keep di Terminal                        ║"
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

# Cek koneksi internet
check_internet() {
    print_step "Mengecek koneksi internet..."
    if ping -c 1 google.com &> /dev/null || ping -c 1 github.com &> /dev/null; then
        print_success "Internet terhubung"
        return 0
    else
        print_error "Tidak ada koneksi internet"
        return 1
    fi
}

# Cek dan install Python
check_python() {
    print_step "Mengecek Python..."
    
    if command -v python3 &> /dev/null; then
        python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_success "Python $python_version terinstall"
        return 0
    else
        print_info "Python 3 belum terinstall"
        install_python
    fi
}

install_python() {
    echo ""
    print_info "Menginstall Python 3..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3 python3-pip
        else
            print_error "Tidak bisa install Python otomatis"
            echo "Silakan install Python 3 manual dari: https://python.org"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install python3
        else
            print_error "Homebrew tidak ditemukan"
            echo "Install Homebrew dulu: /bin/bash -c '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'"
            exit 1
        fi
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        print_error "Untuk Windows, download Python manual dari:"
        echo "https://www.python.org/downloads/"
        echo ""
        echo "Jangan lupa centang 'Add Python to PATH' saat install!"
        exit 1
    else
        print_error "OS tidak dikenal"
        exit 1
    fi
    
    print_success "Python 3 berhasil diinstall"
}

# Download icon dari internet
download_icons() {
    print_step "Mendownload icon aplikasi..."
    
    cd ~/.terminal-keep-app
    mkdir -p icons
    
    if command -v wget &> /dev/null; then
        DOWNLOADER="wget -q"
    elif command -v curl &> /dev/null; then
        DOWNLOADER="curl -s -o"
    else
        print_info "wget/curl tidak ditemukan, membuat icon placeholder..."
        create_placeholder_icons
        return
    fi
    
    # Download icon dari berbagai sumber
    $DOWNLOADER icons/icon16.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    $DOWNLOADER icons/icon32.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    $DOWNLOADER icons/icon64.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    $DOWNLOADER icons/icon128.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    $DOWNLOADER icons/icon256.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    $DOWNLOADER icons/icon512.png "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/sticky-note.svg" 2>/dev/null || create_single_icon
    
    print_success "Icon berhasil didownload"
    
    if [ -f icons/icon512.png ]; then
        cp icons/icon512.png icon.png
    elif [ -f icons/icon256.png ]; then
        cp icons/icon256.png icon.png
    elif [ -f icons/icon128.png ]; then
        cp icons/icon128.png icon.png
    else
        cp icons/icon64.png icon.png 2>/dev/null || create_single_icon
    fi
}

# Buat icon placeholder
create_placeholder_icons() {
    print_info "Membuat icon sederhana..."
    
    cd ~/.terminal-keep-app/icons
    
    if command -v python3 &> /dev/null; then
        python3 -c "
from PIL import Image, ImageDraw
import os

def create_icon(size, filename):
    img = Image.new('RGB', (size, size), color=(66, 133, 244))
    draw = ImageDraw.Draw(img)
    margin = size // 4
    draw.rectangle([margin, margin, size-margin, size-margin], fill=(255, 255, 255))
    line_spacing = size // 8
    for i in range(3):
        y = margin + (i+1) * line_spacing
        draw.line([margin+5, y, size-margin-5, y], fill=(66, 133, 244), width=2)
    img.save(filename)

sizes = [16, 32, 64, 128, 256, 512]
for s in sizes:
    try:
        create_icon(s, f'icon{s}.png')
    except:
        pass
" 2>/dev/null || create_fallback_icon
    else
        create_fallback_icon
    fi
}

create_fallback_icon() {
    echo "TK" > icon16.txt
    echo "TK" > icon32.txt
    echo "TK" > icon64.txt
    echo "TK" > icon128.txt
    echo "TK" > icon256.txt
    echo "TK" > icon512.txt
    cp icon64.txt ../icon.txt
}

# Buat file aplikasi utama
create_app_files() {
    print_step "Membuat file aplikasi..."
    
    mkdir -p ~/.terminal-keep-app
    cd ~/.terminal-keep-app
    
    # Buat file main.py
    cat > main.py << 'EOF'
#!/usr/bin/env python3
"""
TERMINAL KEEP - Aplikasi Catatan seperti Google Keep
"""

import os
import sys
import sqlite3
import getpass
import base64
from datetime import datetime
from pathlib import Path

# ==================== KEAMANAN ====================
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import bcrypt
except ImportError:
    print("Menginstall library yang diperlukan...")
    os.system("pip install cryptography bcrypt")
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import bcrypt

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
        home = Path.home()
        db_dir = home / '.terminal-keep-data'
        db_dir.mkdir(exist_ok=True)
        self.db_path = db_dir / 'catatan.db'
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

# ==================== TAMPILAN ====================
def bersih_layar():
    os.system('cls' if os.name == 'nt' else 'clear')

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
        nilai = input(prompt).strip()
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
        print("║         SELAMAT DATANG DI TERMINAL KEEP        ║")
        print("║         Aplikasi Catatan Pribadi mu            ║")
        print("╚════════════════════════════════════════════════╝")
        print(f"{Warna.RESET}")
        
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
            tampil_header("MENU UTAMA - TERMINAL KEEP")
            print(f"{Warna.BIRU}1.{Warna.RESET} 📝 Lihat Catatan")
            print(f"{Warna.BIRU}2.{Warna.RESET} ➕ Buat Catatan Baru")
            print(f"{Warna.BIRU}3.{Warna.RESET} 🔍 Cari Catatan")
            print(f"{Warna.BIRU}4.{Warna.RESET} 📦 Arsip")
            print(f"{Warna.BIRU}5.{Warna.RESET} 🚪 Logout")
            print(f"{Warna.BIRU}6.{Warna.RESET} ❌ Keluar")
            
            pilihan = input_user("Pilih (1-6): ")
            
            if pilihan == '1':
                self.lihat_catatan()
            elif pilihan == '2':
                self.buat_catatan()
            elif pilihan == '3':
                self.cari_catatan()
            elif pilihan == '4':
                self.lihat_arsip()
            elif pilihan == '5':
                self.db.user_aktif = None
                print(f"{Warna.KUNING}Logout berhasil{Warna.RESET}")
                input("\nTekan Enter untuk lanjut...")
                return
            elif pilihan == '6':
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
        
        print(f"\nKosongkan untuk mempertahankan nilai lama")
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

    # Buat file requirements
    cat > requirements.txt << 'EOF'
cryptography
bcrypt
EOF

    # Buat file README
    cat > README.md << 'EOF'
# Terminal Keep 📝

Aplikasi catatan pribadi seperti Google Keep yang berjalan di terminal.

## Fitur
- 🔐 Login dengan password
- 📝 Buat catatan dengan judul dan isi
- 🎨 Pilih warna catatan
- 📌 Pin catatan penting
- 📦 Arsip catatan lama
- 🔍 Cari catatan
- 🔒 Semua catatan dienkripsi

## Cara Penggunaan
1. Buka terminal
2. Ketik: `cd ~/.terminal-keep-app`
3. Jalankan: `python3 main.py`
4. Login atau daftar akun baru
5. Mulai mencatat!

## Data
Semua catatan tersimpan di: `~/.terminal-keep-data/`

Selamat mencoba! 😊
EOF

    # Buat file untuk Windows
    cat > jalankan.bat << 'EOF'
@echo off
cd /d %USERPROFILE%\.terminal-keep-app
python main.py
pause
EOF

    # Buat file untuk Linux/Mac
    cat > jalankan.sh << 'EOF'
#!/bin/bash
cd ~/.terminal-keep-app
python3 main.py
EOF
    chmod +x jalankan.sh
    
    print_success "File aplikasi selesai dibuat"
}

# Install dependencies
install_dependencies() {
    print_step "Menginstall library Python..."
    
    cd ~/.terminal-keep-app
    
    python3 -m ensurepip --upgrade &> /dev/null
    python3 -m pip install --user cryptography bcrypt
    
    print_success "Library berhasil diinstall"
}

# Buat shortcut di desktop
create_shortcut() {
    print_step "Membuat shortcut..."
    
    ICON_PATH="$HOME/.terminal-keep-app/icon.png"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        mkdir -p ~/.local/share/applications
        mkdir -p ~/Desktop
        
        cat > ~/.local/share/applications/terminal-keep.desktop << EOF
[Desktop Entry]
Name=Terminal Keep
Comment=Aplikasi Catatan Pribadi seperti Google Keep
Exec=bash -c "cd $HOME/.terminal-keep-app && python3 main.py"
Icon=$ICON_PATH
Terminal=true
Type=Application
Categories=Office;Utility;
Keywords=notes;keep;terminal;
EOF
        
        cp ~/.local/share/applications/terminal-keep.desktop ~/Desktop/
        chmod +x ~/Desktop/terminal-keep.desktop
        
        print_success "Shortcut dibuat di Desktop dan Menu Aplikasi"
        
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        APP_NAME="Terminal Keep"
        APP_PATH="$HOME/Desktop/$APP_NAME.app"
        
        mkdir -p "$APP_PATH/Contents/MacOS"
        mkdir -p "$APP_PATH/Contents/Resources"
        
        cp "$ICON_PATH" "$APP_PATH/Contents/Resources/icon.icns" 2>/dev/null || true
        
        cat > "$APP_PATH/Contents/MacOS/$APP_NAME" << EOF
#!/bin/bash
cd "$HOME/.terminal-keep-app"
python3 main.py
EOF
        chmod +x "$APP_PATH/Contents/MacOS/$APP_NAME"
        
        cat > "$APP_PATH/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>CFBundleIdentifier</key>
    <string>com.terminal.keep</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>
EOF
        
        print_success "Shortcut dibuat di Desktop"
        
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        cp ~/.terminal-keep-app/jalankan.bat ~/Desktop/TerminalKeep.bat
        print_success "Shortcut dibuat di Desktop"
    fi
}

# Buat uninstaller
create_uninstaller() {
    cat > ~/.terminal-keep-app/uninstall.sh << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Menghapus Terminal Keep..."

rm -rf ~/.terminal-keep-app
rm -rf ~/.terminal-keep-data
rm -f ~/.local/share/applications/terminal-keep.desktop
rm -f ~/Desktop/terminal-keep.desktop
rm -f ~/Desktop/TerminalKeep.desktop
rm -rf ~/Desktop/Terminal\ Keep.app
rm -f ~/Desktop/TerminalKeep.bat

echo -e "${GREEN}✓ Terminal Keep telah dihapus${NC}"
EOF
    chmod +x ~/.terminal-keep-app/uninstall.sh
}

# Cek dependencies tambahan
check_icon_dependencies() {
    if command -v python3 &> /dev/null; then
        python3 -c "from PIL import Image" 2>/dev/null || {
            print_info "Menginstall PIL untuk pembuatan icon..."
            python3 -m pip install --user pillow 2>/dev/null
        }
    fi
}

# Tampilkan instruksi
show_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
    echo "║               INSTALASI SELESAI! 🎉                        ║"
    echo "╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}CARA MENGGUNAKAN:${NC}"
    echo ""
    echo -e "${BLUE}1.${NC} Buka Terminal/Command Prompt"
    echo ""
    echo -e "${BLUE}2.${NC} Jalankan perintah:"
    echo "   cd ~/.terminal-keep-app"
    echo "   python3 main.py"
    echo ""
    echo -e "${BLUE}3.${NC} ATAU double-click shortcut di Desktop"
    echo ""
    echo -e "${GREEN}Fitur Aplikasi:${NC}"
    echo "   • Login dengan password"
    echo "   • Buat catatan dengan warna"
    echo "   • Pin catatan penting"
    echo "   • Arsip catatan lama"
    echo "   • Cari catatan"
    echo "   • Semua data dienkripsi"
    echo ""
    echo -e "${YELLOW}Data tersimpan di: ~/.terminal-keep-data/${NC}"
    echo ""
    echo -e "${CYAN}Untuk menghapus:${NC}"
    echo "   Jalankan: ~/.terminal-keep-app/uninstall.sh"
    echo ""
}

# ==================== MAIN ====================
main() {
    print_header
    
    echo -e "${YELLOW}Installer ini akan:${NC}"
    echo "  ✓ Cek dan install Python 3 (jika perlu)"
    echo "  ✓ Download icon aplikasi"
    echo "  ✓ Buat aplikasi Terminal Keep"
    echo "  ✓ Install library yang diperlukan"
    echo "  ✓ Buat shortcut di Desktop"
    echo ""
    
    read -p "Tekan Enter untuk memulai instalasi (Ctrl+C untuk batal)..."
    
    check_internet || exit 1
    check_python
    
    mkdir -p ~/.terminal-keep-app
    create_app_files
    check_icon_dependencies
    download_icons
    install_dependencies
    create_shortcut
    create_uninstaller
    show_instructions
}

main
