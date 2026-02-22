#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
print_header() { clear; echo -e "${PURPLE}╔════════════════════════════════════════════════════════════╗\n║              TERMINAL KEEP - INSTALLER                      ║\n╚════════════════════════════════════════════════════════════╝${NC}\n"; }
print_step() { echo -e "${CYAN}➜ $1${NC}"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ $1${NC}"; }

check_python() {
    print_step "Mengecek Python..."
    if command -v python3 &> /dev/null; then
        python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_success "Python $python_version terinstall"
        return 0
    else
        print_error "Python 3 tidak ditemukan. Install dulu: sudo apt install python3 python3-pip"
        exit 1
    fi
}

create_app_files() {
    print_step "Membuat file aplikasi..."
    mkdir -p ~/.terminal-keep-app
    cd ~/.terminal-keep-app
    
    cat > main.py << 'EOF'
#!/usr/bin/env python3
import os, sys, sqlite3, getpass, base64
from pathlib import Path
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

class Warna:
    HEADER = '\033[95m'; BIRU = '\033[94m'; HIJAU = '\033[92m'; KUNING = '\033[93m'
    MERAH = '\033[91m'; PUTIH = '\033[97m'; UNGU = '\033[95m'; CYAN = '\033[96m'
    RESET = '\033[0m'; BOLD = '\033[1m'
    CATATAN = {'putih': PUTIH, 'merah': MERAH, 'hijau': HIJAU, 'kuning': KUNING, 'biru': BIRU, 'ungu': UNGU, 'cyan': CYAN}

class Keamanan:
    def __init__(self): self.salt = None; self.key = None; self.fernet = None
    def buat_salt(self): return os.urandom(16)
    def buat_kunci(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    def hash_password(self, password): return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    def cek_password(self, password, hashed): return bcrypt.checkpw(password.encode(), hashed)
    def enkrip(self, teks): return self.fernet.encrypt(teks.encode())
    def dekrip(self, teks_enkrip): return self.fernet.decrypt(teks_enkrip).decode()
    def init_user(self, password, salt=None):
        if salt: self.salt = salt
        else: self.salt = self.buat_salt()
        self.key = self.buat_kunci(password, self.salt)
        self.fernet = Fernet(self.key); return self.salt

class Database:
    def __init__(self):
        home = Path.home(); db_dir = home / '.terminal-keep-data'; db_dir.mkdir(exist_ok=True)
        self.db_path = db_dir / 'catatan.db'; self.conn = None
        self.keamanan = Keamanan(); self.user_aktif = None
    def connect(self):
        self.conn = sqlite3.connect(str(self.db_path)); self.buat_tabel()
    def disconnect(self):
        if self.conn: self.conn.close()
    def buat_tabel(self):
        cursor = self.conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt BLOB NOT NULL, dibuat TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cursor.execute('CREATE TABLE IF NOT EXISTS catatan (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, judul TEXT NOT NULL, isi BLOB NOT NULL, warna TEXT DEFAULT "putih", dipin BOOLEAN DEFAULT 0, diarsip BOOLEAN DEFAULT 0, dibuat TIMESTAMP DEFAULT CURRENT_TIMESTAMP, diupdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id))')
        self.conn.commit()
    def daftar(self, username, password):
        try:
            cursor = self.conn.cursor(); salt = self.keamanan.buat_salt()
            password_hash = self.keamanan.hash_password(password)
            cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', (username, password_hash, salt))
            self.conn.commit(); return True
        except sqlite3.IntegrityError: return False
    def login(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            user_id, password_hash, salt = result
            if self.keamanan.cek_password(password, password_hash):
                self.user_aktif = {'id': user_id, 'username': username}
                self.keamanan.init_user(password, salt); return True
        return False
    def tambah_catatan(self, judul, isi, warna='putih'):
        if not self.user_aktif: return None
        isi_enkrip = self.keamanan.enkrip(isi); cursor = self.conn.cursor()
        cursor.execute('INSERT INTO catatan (user_id, judul, isi, warna) VALUES (?, ?, ?, ?)', (self.user_aktif['id'], judul, isi_enkrip, warna))
        self.conn.commit(); return cursor.lastrowid
    def ambil_catatan(self, include_arsip=False):
        if not self.user_aktif: return []
        cursor = self.conn.cursor()
        if include_arsip: query = 'SELECT * FROM catatan WHERE user_id = ? ORDER BY dipin DESC, diupdate DESC'
        else: query = 'SELECT * FROM catatan WHERE user_id = ? AND diarsip = 0 ORDER BY dipin DESC, diupdate DESC'
        cursor.execute(query, (self.user_aktif['id'],)); catatan = cursor.fetchall()
        hasil = []
        for catat in catatan:
            catat_list = list(catat)
            try: catat_list[3] = self.keamanan.dekrip(catat_list[3])
            except: catat_list[3] = "[Gagal didekrip]"
            hasil.append(tuple(catat_list))
        return hasil
    def update_catatan(self, catatan_id, judul=None, isi=None, warna=None, dipin=None):
        if not self.user_aktif: return False
        updates = []; params = []
        if judul: updates.append("judul = ?"); params.append(judul)
        if isi: isi_enkrip = self.keamanan.enkrip(isi); updates.append("isi = ?"); params.append(isi_enkrip)
        if warna: updates.append("warna = ?"); params.append(warna)
        if dipin is not None: updates.append("dipin = ?"); params.append(1 if dipin else 0)
        updates.append("diupdate = CURRENT_TIMESTAMP")
        if not updates: return False
        query = f"UPDATE catatan SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
        params.extend([catatan_id, self.user_aktif['id']])
        cursor = self.conn.cursor(); cursor.execute(query, params); self.conn.commit()
        return cursor.rowcount > 0
    def arsip_catatan(self, catatan_id, arsip=True):
        if not self.user_aktif: return False
        cursor = self.conn.cursor()
        cursor.execute('UPDATE catatan SET diarsip = ?, diupdate = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?', (1 if arsip else 0, catatan_id, self.user_aktif['id']))
        self.conn.commit(); return cursor.rowcount > 0
    def hapus_catatan(self, catatan_id):
        if not self.user_aktif: return False
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM catatan WHERE id = ? AND user_id = ?', (catatan_id, self.user_aktif['id']))
        self.conn.commit(); return cursor.rowcount > 0
    def cari_catatan(self, query):
        if not self.user_aktif: return []
        semua = self.ambil_catatan(include_arsip=True); hasil = []
        for catat in semua:
            if query.lower() in catat[2].lower() or query.lower() in catat[3].lower(): hasil.append(catat)
        return hasil

def bersih_layar(): os.system('cls' if os.name == 'nt' else 'clear')
def tampil_header(judul): print(f"\n{Warna.HEADER}{Warna.BOLD}╔{'═'*50}╗\n║{judul:^50}║\n╚{'═'*50}╝{Warna.RESET}\n")
def tampil_catatan(catatan, tampil_id=True):
    id, user_id, judul, isi, warna, dipin, diarsip, dibuat, diupdate = catatan
    warna_code = Warna.CATATAN.get(warna, Warna.PUTIH); pin = "📌 " if dipin else ""; arsip = "📦 " if diarsip else ""
    print(f"\n{warna_code}{'─'*50}")
    if tampil_id: print(f"ID: {id}")
    print(f"{pin}{arsip}{judul}\n{warna_code}{'─'*50}\n{isi}\n{warna_code}Dibuat: {dibuat}")
    if diupdate != dibuat: print(f"Diupdate: {diupdate}")
    print(f"{warna_code}{'─'*50}{Warna.RESET}")
def input_user(prompt, boleh_kosong=False):
    while True:
        nilai = input(prompt).strip()
        if nilai or boleh_kosong: return nilai
        print(f"{Warna.MERAH}Input tidak boleh kosong{Warna.RESET}")
def konfirmasi(prompt): return input(f"{prompt} (y/N): ").strip().lower() == 'y'

class TerminalKeep:
    def __init__(self): self.db = Database(); self.running = True
    def mulai(self):
        self.db.connect(); bersih_layar()
        print(f"{Warna.HIJAU}{Warna.BOLD}\n╔════════════════════════════════════════════════╗\n║         SELAMAT DATANG DI TERMINAL KEEP        ║\n║         Aplikasi Catatan Pribadi mu            ║\n╚════════════════════════════════════════════════╝{Warna.RESET}")
        while True:
            print(f"\n{Warna.BIRU}1.{Warna.RESET} Login\n{Warna.BIRU}2.{Warna.RESET} Daftar Baru\n{Warna.BIRU}3.{Warna.RESET} Keluar")
            pilihan = input_user("Pilih (1-3): ")
            if pilihan == '1':
                if self.login(): self.menu_utama()
            elif pilihan == '2': self.daftar()
            elif pilihan == '3': self.selesai(); return
            else: print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}")
    def login(self):
        print(f"\n{Warna.HEADER}=== LOGIN ==={Warna.RESET}")
        username = input_user("Username: "); password = getpass.getpass("Password: ")
        if self.db.login(username, password):
            print(f"{Warna.HIJAU}✓ Selamat datang, {username}!{Warna.RESET}"); return True
        else: print(f"{Warna.MERAH}✗ Username atau password salah{Warna.RESET}"); input("\nTekan Enter..."); return False
    def daftar(self):
        print(f"\n{Warna.HEADER}=== DAFTAR AKUN BARU ==={Warna.RESET}")
        username = input_user("Username: ")
        while True:
            password = getpass.getpass("Password (min 6 karakter): ")
            if len(password) < 6: print(f"{Warna.MERAH}Password minimal 6 karakter{Warna.RESET}"); continue
            confirm = getpass.getpass("Ulangi password: ")
            if password == confirm: break
            print(f"{Warna.MERAH}Password tidak cocok{Warna.RESET}")
        if self.db.daftar(username, password): print(f"{Warna.HIJAU}✓ Akun berhasil dibuat!{Warna.RESET}")
        else: print(f"{Warna.MERAH}✗ Username sudah digunakan{Warna.RESET}")
        input("\nTekan Enter...")
    def menu_utama(self):
        while self.running:
            bersih_layar(); tampil_header("MENU UTAMA - TERMINAL KEEP")
            print(f"{Warna.BIRU}1.{Warna.RESET} 📝 Lihat Catatan\n{Warna.BIRU}2.{Warna.RESET} ➕ Buat Catatan Baru\n{Warna.BIRU}3.{Warna.RESET} 🔍 Cari Catatan\n{Warna.BIRU}4.{Warna.RESET} 📦 Arsip\n{Warna.BIRU}5.{Warna.RESET} 🚪 Logout\n{Warna.BIRU}6.{Warna.RESET} ❌ Keluar")
            pilihan = input_user("Pilih (1-6): ")
            if pilihan == '1': self.lihat_catatan()
            elif pilihan == '2': self.buat_catatan()
            elif pilihan == '3': self.cari_catatan()
            elif pilihan == '4': self.lihat_arsip()
            elif pilihan == '5': self.db.user_aktif = None; print(f"{Warna.KUNING}Logout berhasil{Warna.RESET}"); input("\nTekan Enter..."); return
            elif pilihan == '6':
                if konfirmasi("Yakin mau keluar?"): self.running = False
            else: print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}"); input("Tekan Enter...")
    def lihat_catatan(self):
        bersih_layar(); tampil_header("CATATAN SAYA"); catatan = self.db.ambil_catatan()
        if not catatan: print(f"{Warna.KUNING}Belum ada catatan. Buat catatan baru!{Warna.RESET}"); input("\nTekan Enter..."); return
        for catat in catatan: tampil_catatan(catat)
        self.menu_aksi_catatan()
    def lihat_arsip(self):
        bersih_layar(); tampil_header("ARSIP"); catatan = self.db.ambil_catatan(include_arsip=True)
        catatan_arsip = [c for c in catatan if c[6]]
        if not catatan_arsip: print(f"{Warna.KUNING}Belum ada catatan di arsip{Warna.RESET}"); input("\nTekan Enter..."); return
        for catat in catatan_arsip: tampil_catatan(catat)
        self.menu_aksi_catatan()
    def menu_aksi_catatan(self):
        print(f"\n{Warna.BIRU}=== AKSI ==={Warna.RESET}\n1. ✏️  Edit\n2. 📌 Pin/Unpin\n3. 📦 Arsip/Unarsip\n4. 🗑️  Hapus\n5. ↩️  Kembali")
        pilihan = input_user("Pilih aksi (1-5): ")
        if pilihan == '1': self.edit_catatan()
        elif pilihan == '2': self.toggle_pin()
        elif pilihan == '3': self.toggle_arsip()
        elif pilihan == '4': self.hapus_catatan()
        elif pilihan == '5': return
        else: print(f"{Warna.MERAH}Pilihan tidak valid{Warna.RESET}"); input("Tekan Enter...")
    def buat_catatan(self):
        bersih_layar(); tampil_header("BUAT CATATAN BARU"); judul = input_user("Judul: ")
        print("Isi catatan (ketik '.' di baris baru untuk selesai):"); baris = []
        while True:
            line = input()
            if line == '.': break
            baris.append(line)
        isi = '\n'.join(baris)
        print(f"\nWarna tersedia: putih, merah, hijau, kuning, biru, ungu, cyan")
        warna = input_user("Warna (default: putih): ").lower()
        if warna not in ['putih', 'merah', 'hijau', 'kuning', 'biru', 'ungu', 'cyan']: warna = 'putih'
        catatan_id = self.db.tambah_catatan(judul, isi, warna)
        print(f"{Warna.HIJAU}✓ Catatan berhasil dibuat! (ID: {catatan_id}){Warna.RESET}"); input("\nTekan Enter...")
    def edit_catatan(self):
        catatan_id = input_user("ID catatan yang mau diedit: ")
        try: catatan_id = int(catatan_id)
        except: print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}"); input("Tekan Enter..."); return
        catatan = self.db.ambil_catatan(include_arsip=True); catatan_sekarang = None
        for catat in catatan:
            if catat[0] == catatan_id: catatan_sekarang = catat; break
        if not catatan_sekarang: print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}"); input("Tekan Enter..."); return
        print(f"\nKosongkan untuk mempertahankan nilai lama")
        judul_baru = input_user(f"Judul [{catatan_sekarang[2]}]: ", boleh_kosong=True)
        if not judul_baru: judul_baru = catatan_sekarang[2]
        print(f"Isi lama:\n{catatan_sekarang[3]}")
        print("Isi baru (ketik '.' di baris baru untuk selesai, kosongkan jika tidak diubah):"); baris = []
        while True:
            line = input()
            if line == '.': break
            baris.append(line)
        isi_baru = '\n'.join(baris) if baris else None
        if self.db.update_catatan(catatan_id, judul=judul_baru, isi=isi_baru): print(f"{Warna.HIJAU}✓ Catatan berhasil diupdate!{Warna.RESET}")
        else: print(f"{Warna.MERAH}✗ Gagal update catatan{Warna.RESET}")
        input("Tekan Enter...")
    def toggle_pin(self):
        catatan_id = input_user("ID catatan: ")
        try: catatan_id = int(catatan_id)
        except: print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}"); input("Tekan Enter..."); return
        catatan = self.db.ambil_catatan(include_arsip=True)
        for catat in catatan:
            if catat[0] == catatan_id:
                status_baru = not catat[5]
                if self.db.update_catatan(catatan_id, dipin=status_baru): print(f"{Warna.HIJAU}✓ Catatan {'di-pin' if status_baru else 'di-unpin'}{Warna.RESET}")
                else: print(f"{Warna.MERAH}✗ Gagal update{Warna.RESET}")
                break
        else: print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}")
        input("Tekan Enter...")
    def toggle_arsip(self):
        catatan_id = input_user("ID catatan: ")
        try: catatan_id = int(catatan_id)
        except: print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}"); input("Tekan Enter..."); return
        catatan = self.db.ambil_catatan(include_arsip=True)
        for catat in catatan:
            if catat[0] == catatan_id:
                status_baru = not catat[6]
                if self.db.arsip_catatan(catan_id, status_baru): print(f"{Warna.HIJAU}✓ Catatan {'di-arsip' if status_baru else 'di-unarsip'}{Warna.RESET}")
                else: print(f"{Warna.MERAH}✗ Gagal update{Warna.RESET}")
                break
        else: print(f"{Warna.MERAH}Catatan tidak ditemukan{Warna.RESET}")
        input("Tekan Enter...")
    def hapus_catatan(self):
        catatan_id = input_user("ID catatan yang mau dihapus: ")
        try: catatan_id = int(catatan_id)
        except: print(f"{Warna.MERAH}ID tidak valid{Warna.RESET}"); input("Tekan Enter..."); return
        if konfirmasi(f"Yakin mau hapus catatan #{catatan_id}?"):
            if self.db.hapus_catatan(catatan_id): print(f"{Warna.HIJAU}✓ Catatan dihapus{Warna.RESET}")
            else: print(f"{Warna.MERAH}✗ Gagal hapus{Warna.RESET}")
        else: print("Dibatalkan")
        input("Tekan Enter...")
    def cari_catatan(self):
        bersih_layar(); tampil_header("CARI CATATAN"); query = input_user("Kata kunci: "); hasil = self.db.cari_catatan(query)
        if not hasil: print(f"{Warna.KUNING}Tidak ada catatan dengan kata '{query}'{Warna.RESET}")
        else:
            print(f"\nDitemukan {len(hasil)} catatan:")
            for catat in hasil: tampil_catatan(catat)
        input("\nTekan Enter...")
    def selesai(self): self.db.disconnect(); print(f"\n{Warna.HIJAU}Sampai jumpa! 👋{Warna.RESET}")

if __name__ == "__main__":
    try:
        app = TerminalKeep(); app.mulai()
    except KeyboardInterrupt: print(f"\n{Warna.KUNING}Dadah! 👋{Warna.RESET}")
    except Exception as e: print(f"{Warna.MERAH}Error: {e}{Warna.RESET}"); input("Tekan Enter...")
EOF

    cat > jalankan.sh << 'EOF'
#!/bin/bash
cd ~/.terminal-keep-app
python3 main.py
EOF
    chmod +x jalankan.sh
    print_success "File aplikasi selesai dibuat"
}

install_dependencies() {
    print_step "Menginstall library Python..."
    cd ~/.terminal-keep-app
    python3 -m pip install --user cryptography bcrypt 2>/dev/null
    print_success "Library berhasil diinstall"
}

create_shortcut() {
    print_step "Membuat shortcut..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        mkdir -p ~/.local/share/applications ~/Desktop
        cat > ~/.local/share/applications/terminal-keep.desktop << EOF
[Desktop Entry]
Name=Terminal Keep
Comment=Aplikasi Catatan Pribadi
Exec=bash -c "cd $HOME/.terminal-keep-app && python3 main.py"
Icon=$HOME/.terminal-keep-app/icon.png
Terminal=true
Type=Application
Categories=Office;
EOF
        cp ~/.local/share/applications/terminal-keep.desktop ~/Desktop/
        chmod +x ~/Desktop/terminal-keep.desktop
    fi
    print_success "Shortcut dibuat"
}

create_uninstaller() {
    cat > ~/.terminal-keep-app/uninstall.sh << 'EOF'
#!/bin/bash
echo "Menghapus Terminal Keep..."
rm -rf ~/.terminal-keep-app
rm -rf ~/.terminal-keep-data
rm -f ~/.local/share/applications/terminal-keep.desktop
rm -f ~/Desktop/terminal-keep.desktop
echo "✓ Terminal Keep telah dihapus"
EOF
    chmod +x ~/.terminal-keep-app/uninstall.sh
}

show_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
    echo "║               INSTALASI SELESAI! 🎉                        ║"
    echo "╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "CARA MENGGUNAKAN:"
    echo "  cd ~/.terminal-keep-app"
    echo "  python3 main.py"
    echo ""
    echo "Atau klik shortcut di Desktop"
    echo ""
    echo "Uninstall: ~/.terminal-keep-app/uninstall.sh"
    echo ""
}

main() {
    print_header
    echo -e "${YELLOW}Installer akan membuat aplikasi Terminal Keep${NC}\n"
    read -p "Tekan Enter untuk memulai..."
    check_python
    mkdir -p ~/.terminal-keep-app
    create_app_files
    install_dependencies
    create_shortcut
    create_uninstaller
    show_instructions
}

main
