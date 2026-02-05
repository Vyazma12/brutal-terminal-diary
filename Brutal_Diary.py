from __future__ import annotations
import base64
import datetime
import getpass
import hashlib
import hmac
import json
import os
import secrets
import statistics
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import List, Optional

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

DB_PATH = Path.home() / '.brutal_diary.json'
LOCK_DAYS = 30
KDF_ITERATIONS = 390_000
VALIDATOR_PLAINTEXT = "brutal-diary-validator-v2"

C_RESET  = "\033[0m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BOLD   = "\033[1m"

PROMPTS = [
    "Apa satu kebohongan kecil yang kamu bilang ke diri sendiri hari ini?",
    "Kalau hidupmu punya soundtrack, lagu apa yang lagi replay sekarang?",
    "Apa yang bikin kamu merasa capek — orang, ide, atau rutinitas?",
    "Sebutkan satu hal yang kamu hindari bilang ke orang lain. Kenapa?",
    "Hal apa yang kamu anggap paling membatasimu akhir-akhir ini?",
    "Kapan terakhir kali kamu merasa bangga ke diri sendiri? Ceritakan sedikit.",
    "Apa satu hal yang kamu pengin stop melakukan selama seminggu?",
    "Sebut satu kebiasaan kecil yang justru bikin mood kamu turun.",
    "Kalau kamu bisa bilang satu kalimat ke versi dirimu 5 tahun lalu, apa?",
]


def color(text: str, code: str) -> str:
    return f"{code}{text}{C_RESET}"


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)



def get_hash_key(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    kl = len(key)
    for i, b in enumerate(data):
        out.append(b ^ key[i % kl])
    return bytes(out)


def xor_encrypt_with_hmac(plaintext: bytes, password: str) -> str:
    key = get_hash_key(password)
    hmac_key = hashlib.sha256(key + b"-hmac").digest()
    cipher = xor_bytes(plaintext, key)
    tag = hmac.new(hmac_key, cipher, hashlib.sha256).digest()
    blob = tag + cipher
    return base64.b64encode(blob).decode('utf-8')


def xor_decrypt_with_hmac(b64_blob: str, password: str) -> Optional[bytes]:
    try:
        blob = base64.b64decode(b64_blob.encode('utf-8'))
        if len(blob) < 32:
            return None
        tag = blob[:32]
        cipher = blob[32:]
        key = get_hash_key(password)
        hmac_key = hashlib.sha256(key + b"-hmac").digest()
        expected = hmac.new(hmac_key, cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return None
        return xor_bytes(cipher, key)
    except Exception:
        return None



def derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))



def open_editor(initial_text: str = "") -> str:
    editor = os.environ.get('EDITOR', 'nano' if os.name == 'posix' else 'notepad')
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.tmp', delete=False, encoding='utf-8') as tf:
        tf.write(initial_text)
        tf.flush()
        path = tf.name
    try:
        rc = subprocess.call([editor, path])
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception as e:
        print(color(f"Gagal buka editor: {e}", C_RED))
        return input("Fallback input: ")
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def draw_bar_chart(data: List[int], height: int = 5) -> str:
    if not data:
        return ""
    lines = []
    max_val = 10
    for h in range(height, 0, -1):
        line = f"{int((h/height)*max_val):>2} | "
        threshold = (h / height) * max_val
        for val in data:
            line += "█ " if val >= threshold else "  "
        lines.append(line)
    lines.append("   " + "—" * (len(data)*2 + 1))
    return "\n".join(lines)


class EncryptionManager:
    def __init__(self, db_meta: Optional[dict] = None):
        self.kdf = None
        self.salt = None
        self.passphrase = None
        self.fernet = None
        if db_meta:
            self.kdf = db_meta.get('kdf')
            salt_b64 = db_meta.get('salt')
            if salt_b64:
                try:
                    self.salt = base64.b64decode(salt_b64)
                except Exception:
                    self.salt = None

    def setup_new(self, want_fernet: bool):
        self.salt = secrets.token_bytes(16)
        self.kdf = 'fernet' if (want_fernet and CRYPTO_AVAILABLE) else 'xor'

    def create_validator_blob(self) -> str:
        if self.kdf == 'fernet' and CRYPTO_AVAILABLE:
            key = derive_fernet_key(self.passphrase, self.salt)
            self.fernet = Fernet(key)
            return self.fernet.encrypt(VALIDATOR_PLAINTEXT.encode('utf-8')).decode('utf-8')
        else:
            return xor_encrypt_with_hmac(VALIDATOR_PLAINTEXT.encode('utf-8'), self.passphrase)

    def prompt_passphrase_and_unlock(self, require_validator: Optional[str] = None) -> bool:
        for _ in range(3):
            p = getpass.getpass("Passphrase: ")
            if not p:
                print("Passphrase kosong.")
                continue
            try:
                if self.kdf == 'fernet' and CRYPTO_AVAILABLE:
                    key = derive_fernet_key(p, self.salt)
                    f = Fernet(key)
                    if require_validator:
                        try:
                            dec = f.decrypt(require_validator.encode('utf-8'))
                            if dec.decode('utf-8') != VALIDATOR_PLAINTEXT:
                                print("Passphrase salah.")
                                continue
                        except InvalidToken:
                            print("Passphrase salah.")
                            continue
                    self.fernet = f
                    self.passphrase = p
                    return True
                else:
                    if require_validator:
                        plain = xor_decrypt_with_hmac(require_validator, p)
                        if not plain or plain.decode('utf-8') != VALIDATOR_PLAINTEXT:
                            print("Passphrase salah.")
                            continue
                    self.passphrase = p
                    return True
            except Exception:
                print("Passphrase salah.")
        return False

    def encrypt_bytes(self, plaintext: bytes) -> str:
        if self.kdf == 'fernet' and CRYPTO_AVAILABLE:
            token = self.fernet.encrypt(plaintext)
            return f"fernet${token.decode('utf-8')}"
        else:
            b64 = xor_encrypt_with_hmac(plaintext, self.passphrase)
            return f"xor:v1${b64}"

    def decrypt_bytes(self, stored: str) -> Optional[bytes]:
        if stored.startswith('fernet$') and CRYPTO_AVAILABLE:
            token = stored.split('f', 1)[1]  
            try:
                return self.fernet.decrypt(token.encode('utf-8'))
            except InvalidToken:
                return None
        elif stored.startswith('xor:v1$'):
            b64 = stored.split('$', 1)[1]
            return xor_decrypt_with_hmac(b64, self.passphrase)
        else:
            if self.kdf == 'fernet' and CRYPTO_AVAILABLE:
                try:
                    return self.fernet.decrypt(stored.encode('utf-8'))
                except Exception:
                    return None
            else:
                return xor_decrypt_with_hmac(stored, self.passphrase)


class BrutalDiary:
    def __init__(self, db_path: Path = DB_PATH, lock_days: int = LOCK_DAYS):
        self.db_path = db_path
        self.lock_days = lock_days
        self.db = None
        self.encryption = None
        self._load_or_init()

    def _atomic_write(self, data: dict):
        tmp = self.db_path.with_suffix('.tmp')
        with tmp.open('w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self.db_path)

    def _load_or_init(self):
        if not self.db_path.exists():
            print(color("Belum ada diary. Membuat baru.", C_CYAN))
            want_fernet = CRYPTO_AVAILABLE
            if CRYPTO_AVAILABLE:
                print(color("cryptography tersedia — pakai Fernet.", C_GREEN))
            else:
                print(color("cryptography tidak tersedia — pakai XOR+HMAC fallback.", C_YELLOW))

            self.encryption = EncryptionManager()
            self.encryption.setup_new(want_fernet)

            while True:
                p1 = getpass.getpass("Buat passphrase: ")
                p2 = getpass.getpass("Ulangi passphrase: ")
                if p1 and p1 == p2:
                    self.encryption.passphrase = p1
                    break
                print(color("Passphrase beda atau kosong, coba lagi.", C_YELLOW))

            validator = self.encryption.create_validator_blob()
            meta = {
                'kdf': self.encryption.kdf,
                'salt': base64.b64encode(self.encryption.salt).decode('utf-8'),
                'validator': validator,
                'created': now_utc().isoformat(),
            }
            self.db = {'meta': meta, 'entries': []}
            self._atomic_write(self.db)
            print(color("Diary terinisialisasi dan diamankan.", C_GREEN))
            return

        try:
            with self.db_path.open('r', encoding='utf-8') as f:
                raw = json.load(f)
        except Exception:
            print(color("Gagal baca file diary (mungkin korup). Membuat yang kosong.", C_RED))
            self.db = {'meta': {}, 'entries': []}
            return

        meta = raw.get('meta', {})
        self.encryption = EncryptionManager(db_meta=meta)
        validator = meta.get('validator')
        ok = self.encryption.prompt_passphrase_and_unlock(require_validator=validator)
        if not ok:
            print(color("Gagal buka diary — passphrase salah. Keluar.", C_RED))
            sys.exit(1)

        self.db = raw
        print(color("Diary dibuka.", C_GREEN))

    def today_date(self) -> str:
        return now_utc().date().isoformat()

    def has_entry_today(self) -> bool:
        today = self.today_date()
        return any(e['date'] == today for e in self.db.get('entries', []))

    def add_entry(self, prompt: str, text: str, mood: int):
        cipher = self.encryption.encrypt_bytes(text.encode('utf-8'))
        entry = {
            'date': self.today_date(),
            'time': now_utc().isoformat(),
            'prompt': prompt,
            'text': cipher,
            'mood': mood,
        }
        self.db['entries'].append(entry)
        self._atomic_write(self.db)

    def _entry_unlock_time(self, entry: dict) -> datetime.datetime:
        dt = datetime.datetime.fromisoformat(entry['time'])
        return dt + datetime.timedelta(days=self.lock_days)

    def get_entries(self, locked_only=False, unlocked_only=False) -> List[dict]:
        now = now_utc()
        results = []
        for e in self.db.get('entries', []):
            unlock = self._entry_unlock_time(e)
            is_locked = now < unlock
            if locked_only and not is_locked:
                continue
            if unlocked_only and is_locked:
                continue

            if not is_locked:
                plain_bytes = self.encryption.decrypt_bytes(e['text'])
                text = plain_bytes.decode('utf-8') if plain_bytes else "[Decryption failed]"
            else:
                text = "[LOCKED]"

            e_copy = dict(e)
            e_copy['_decoded_text'] = text
            e_copy['_is_locked'] = is_locked
            e_copy['_days_left'] = max(0, (unlock - now).days)
            results.append(e_copy)
        return results

    def stats_dashboard(self) -> str:
        entries = self.db.get('entries', [])
        if not entries:
            return "No entries yet."
        unlocked = self.get_entries(unlocked_only=True)
        locked = self.get_entries(locked_only=True)
        moods = [e.get('mood', 5) for e in entries]
        avg_mood = statistics.mean(moods) if moods else 0
        recent = moods[-15:]
        chart = draw_bar_chart(recent)
        return textwrap.dedent(f"""
        {color('--- STATISTICS ---', C_CYAN)}
        Total Entries : {len(entries)}
        Locked        : {color(str(len(locked)), C_RED)}
        Readable      : {color(str(len(unlocked)), C_GREEN)}
        Average Mood  : {avg_mood:.1f}/10

        {color('Mood History (Last 15):', C_BOLD)}
        {chart}
        """)


def get_mood_input() -> int:
    while True:
        try:
            val = input(f"Rate your mood today (1-10): ").strip()
            num = int(val)
            if 1 <= num <= 10:
                return num
            print(color("Masukkan angka antara 1 dan 10.", C_YELLOW))
        except ValueError:
            print(color("Angka nggak valid.", C_YELLOW))


def main():
    diary = BrutalDiary()
    print(color("\nBrutal Terminal Diary", C_BOLD))
    print(color(f"Time-Lock: {LOCK_DAYS} days. Jujur ya.", C_GREY))

    while True:
        try:
            raw_input = input(color('\n> ', C_GREEN)).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break

        if not raw_input:
            if diary.has_entry_today():
                print(color("Kamu sudah menulis hari ini.", C_YELLOW))
                continue
            prompt = secrets.choice(PROMPTS)
            print(f"\n{color('PROMPT:', C_CYAN)} {prompt}")
            print(color("(Enter buka editor, atau ketik langsung)", C_GREY))
            initial = input("Draft: ")
            if not initial.strip() or initial.endswith('\\e'):
                final_text = open_editor(initial.replace('\\e', ''))
            else:
                final_text = initial
            if not final_text.strip():
                print(color("Kosong, dibatalkan.", C_RED))
                continue
            mood = get_mood_input()
            diary.add_entry(prompt, final_text, mood)
            print(color("Tersimpan (terenkripsi).", C_GREEN))
            continue

        parts = raw_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == '/help':
            print(textwrap.dedent("""
            /read        : Read unlocked entries
            /search <kw> : Search unlocked entries for keyword
            /stats       : Show mood graph and counts
            /export <f>  : Export JSON (encrypted texts included)
            /quit        : Exit

            * Tekan Enter untuk menulis entri hari ini.
            """))

        elif cmd == '/stats':
            print(diary.stats_dashboard())

        elif cmd == '/read':
            entries = diary.get_entries(unlocked_only=True)
            if not entries:
                print(color("Belum ada yang bisa dibaca.", C_YELLOW))
                continue
            for e in entries:
                print(color("-" * 40, C_GREY))
                print(f"{color(e['date'], C_BOLD)} | Mood: {e['mood']}/10")
                print(f"Q: {e['prompt']}")
                print(f"\n{e['_decoded_text']}\n")

        elif cmd == '/search':
            if not arg:
                print(color("Usage: /search <keyword>", C_YELLOW))
                continue
            entries = diary.get_entries(unlocked_only=True)
            hits = [e for e in entries if arg.lower() in e['_decoded_text'].lower()]
            print(f"Found {len(hits)} matches:")
            for e in hits:
                preview = textwrap.shorten(e['_decoded_text'], width=60)
                print(f"[{e['date']}] {preview}")

        elif cmd == '/export':
            fname = arg or f"diary_backup_{int(now_utc().timestamp())}.json"
            try:
                with open(fname, 'w', encoding='utf-8') as f:
                    json.dump(diary.db, f, indent=2, ensure_ascii=False)
                print(color(f"Exported to {fname}", C_GREEN))
            except Exception as e:
                print(color(f"Export failed: {e}", C_RED))

        elif cmd == '/quit':
            print("Stay safe.")
            break

        else:
            print(color("Perintah tidak dikenal.", C_RED))


if __name__ == '__main__':
    main()
