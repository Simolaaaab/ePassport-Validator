import hashlib
import sys
import os
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# 1. DATI MRZ (Modifica con i tuoi!)
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# 2. UTILITY CRITTOGRAFICHE ICAO
# ==========================================
def derive_key(seed, mode):
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    return d[:8] + d[8:16]

def pad(data):
    return data + b'\x80' + b'\x00' * (7 - (len(data) % 8))

def unpad(data):
    idx = data.rfind(b'\x80')
    if idx == -1: return data
    return data[:idx]

def increment_ssc(ssc):
    val = int.from_bytes(ssc, 'big') + 1
    return val.to_bytes(8, 'big')

def encrypt_3des(key, data, iv=bytes([0]*8)):
    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(data)

def decrypt_3des(key, data, iv=bytes([0]*8)):
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(data)

def calc_mac(key, data):
    ka, kb = key[:8], key[8:16]
    step1 = DES.new(ka, DES.MODE_CBC, bytes([0]*8)).encrypt(data)[-8:]
    step2 = DES.new(kb, DES.MODE_ECB).decrypt(step1)
    return DES.new(ka, DES.MODE_ECB).encrypt(step2)

# ==========================================
# 3. SECURE CHANNEL (Gestione APDU Protette)
# ==========================================
class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc

    def protect_apdu(self, cla, ins, p1, p2, data=None, le=None):
        self.ssc = increment_ssc(self.ssc) 
        
        do_data = b''
        if data:
            padded_data = pad(bytes(data))
            iv = encrypt_3des(self.ks_enc, self.ssc) 
            encrypted = encrypt_3des(self.ks_enc, padded_data, iv)
            do_data = b'\x87' + bytes([len(encrypted)+1]) + b'\x01' + encrypted

        do_le = b''
        if le is not None:
            do_le = b'\x97\x01' + bytes([le])

        do_cmd_header = pad(bytes([cla | 0x0C, ins, p1, p2])) 
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        final_data = do_data + do_le + do_mac
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        if le is not None: apdu += [0x00]
        return apdu

    def unprotect_response(self, resp):
        self.ssc = increment_ssc(self.ssc)
        data = bytes(resp)
        
        # Check MAC e Do87/Do99 parsing semplificato
        idx = 0
        enc_data = b''
        
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87: # Encrypted Data
                # Gestione lunghezza ASN.1 (short o long form)
                if data[idx+1] < 0x80:
                    L = data[idx+1]
                    start = idx + 2
                else:
                    n_bytes = data[idx+1] & 0x7F
                    L = int.from_bytes(data[idx+2 : idx+2+n_bytes], 'big')
                    start = idx + 2 + n_bytes
                
                # Il body inizia con 0x01 (padding indicator) che saltiamo
                enc_data = data[start+1 : start+L]
                idx = start + L
                
            elif tag == 0x99: # Status Word
                idx += 4 # Skip (99 02 SW1 SW2)
            elif tag == 0x8E: # MAC
                idx += 10 # Skip (8E 08 ...MAC...)
            else:
                idx += 1 # Skip unknown junk
        
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            decrypted = decrypt_3des(self.ks_enc, enc_data, iv)
            return unpad(decrypted)
        return b''

    def read_logical_file(self, file_id_bytes, filename_debug):
        """
        Esegue SELECT + READ BINARY Loop
        """
        fid_hex = toHexString(list(file_id_bytes))
        print(f"[*] Tentativo download {filename_debug} (FID: {fid_hex})...")

        # 1. SELECT
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x0C, list(file_id_bytes))
        resp, sw1, sw2 = self.conn.transmit(cmd)
        if (sw1<<8)+sw2 != 0x9000:
            print(f"    ❌ SELECT Fallita: {hex((sw1<<8)+sw2)}")
            return None

        # 2. READ LOOP
        full_data = b''
        offset = 0
        chunk_size = 0xE0 # 224 bytes
        
        while True:
            # Calcolo P1/P2 per offset > 255
            p1 = (offset >> 8) & 0xFF
            p2 = offset & 0xFF
            
            cmd = self.protect_apdu(0x00, 0xB0, p1, p2, None, le=chunk_size)
            resp, sw1, sw2 = self.conn.transmit(cmd)
            
            if (sw1<<8)+sw2 != 0x9000:
                if (sw1<<8)+sw2 == 0x6B00: break # Fine file
                print(f"    ❌ Errore Read a offset {offset}: {hex((sw1<<8)+sw2)}")
                break
            
            chunk = self.unprotect_response(resp)
            if not chunk: break
            
            full_data += chunk
            # print(f"    -> Chunk {len(chunk)} bytes. Totale: {len(full_data)}")
            
            if len(chunk) < chunk_size: break
            offset += len(chunk)

        # 3. VERIFICA VALIDITÀ DATI (Il controllo che mancava!)
        if len(full_data) < 5:
            print(f"    ❌ Errore: File {filename_debug} troppo piccolo ({len(full_data)} bytes). Download fallito.")
            return None
            
        # Controllo header
        first_byte = full_data[0]
        if first_byte not in [0x77, 0x30, 0x60, 0x61]: # 6x sono tag comuni per DG
             print(f"    ⚠️  ATTENZIONE: {filename_debug} inizia con {hex(first_byte)}! Dati corrotti/non decriptati?")
             print(f"       Dump primi byte: {full_data[:8].hex().upper()}")
        else:
            print(f"    ✅ {filename_debug} scaricato correttamente ({len(full_data)} bytes). Header OK ({hex(first_byte)})")

        return full_data

# ==========================================
# 4. MAIN
# ==========================================
def main():
    print("--- ICAO 9303 ROBUST DOWNLOADER ---")
    
    # 1. Calcolo Chiavi
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    print(f"[*] MRZ Info: {mrz_info}")
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc_mrz = derive_key(k_seed, 1)
    k_mac_mrz = derive_key(k_seed, 2)

    # 2. Connessione
    r = readers()
    if not r: sys.exit("No Reader")
    conn = r[0].createConnection()
    conn.connect()
    
    # 3. Auth BAC
    print("[*] Eseguo BAC Authentication...")
    conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]) # Select Applet
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08]) # Get Challenge
    rnd_icc = bytes(resp)
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    
    plaintext = rnd_ifd + rnd_icc + k_ifd
    e_ifd = DES3.new(k_enc_mrz, DES3.MODE_CBC, bytes([0]*8)).encrypt(plaintext)
    mac_ifd = DES.new(k_mac_mrz[:8], DES.MODE_ECB).encrypt(
                DES.new(k_mac_mrz[8:16], DES.MODE_ECB).decrypt(
                    DES.new(k_mac_mrz[:8], DES.MODE_CBC, bytes([0]*8)).encrypt(pad(e_ifd))[-8:]
                )
              )
    
    cmd_auth = [0x00, 0x82, 0x00, 0x00, 0x28] + list(e_ifd) + list(mac_ifd) + [0x00]
    resp, sw1, sw2 = conn.transmit(cmd_auth)
    
    if (sw1<<8)+sw2 != 0x9000:
        print(f"❌ BAC FALLITA: {hex((sw1<<8)+sw2)}")
        print("   Controlla i dati MRZ (Date di nascita e scadenza)!")
        return

    # 4. Calcolo Session Keys
    e_icc = bytes(resp)[:32]
    dec_icc = DES3.new(k_enc_mrz, DES3.MODE_CBC, bytes([0]*8)).decrypt(e_icc)
    k_icc = dec_icc[16:32]
    k_seed_sess = strxor(k_ifd, k_icc)
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    print("✅ Secure Messaging Attivo.")

    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)

    # 5. DOWNLOAD FILE
    # DG1 (File ID 0101)
    dg1 = sc.read_logical_file(b'\x01\x01', "DG1")
    if dg1: 
        with open("dg1.bin", "wb") as f: f.write(dg1)

    # DG2 (File ID 0102)
    dg2 = sc.read_logical_file(b'\x01\x02', "DG2")
    if dg2: 
        with open("dg2.bin", "wb") as f: f.write(dg2)

    # SOD (File ID 011D)
    sod = sc.read_logical_file(b'\x01\x1D', "SOD")
    if sod: 
        with open("sod.bin", "wb") as f: f.write(sod)
        print("\n✅ FILE SOD SCARICATO CORRETTAMENTE. ORA PUOI VALIDARE.")

if __name__ == "__main__":
    main()