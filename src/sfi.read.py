import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# 1. I TUOI DATI (MRZ)
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# 2. IMPLEMENTAZIONE CRITTOGRAFICA ICAO
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
    val = int.from_bytes(ssc, 'big')
    val += 1
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

class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc

    def protect_apdu(self, cla, ins, p1, p2, data=None, le=None):
        self.ssc = increment_ssc(self.ssc) 
        
        # DO 87 (Encrypted Data)
        do_data = b''
        if data:
            padded_data = pad(data)
            iv = encrypt_3des(self.ks_enc, self.ssc) 
            encrypted = encrypt_3des(self.ks_enc, padded_data, iv)
            do_data = b'\x87' + bytes([len(encrypted)+1]) + b'\x01' + encrypted

        # DO 97 (Le)
        do_le = b''
        if le is not None:
            do_le = b'\x97\x01' + bytes([le])

        # Header Mascherato per MAC
        do_cmd_header = pad(bytes([cla | 0x0C, ins, p1, p2])) 

        # MAC
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        final_data = do_data + do_le + do_mac
        
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        if le is not None:
            apdu += [0x00] # Transport Le byte
            
        return apdu

    def unprotect_response(self, resp):
        self.ssc = increment_ssc(self.ssc)
        data = bytes(resp)
        idx = 0
        enc_data = b''
        
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87: 
                length = data[idx+1]
                enc_data = data[idx+3 : idx+2+length]
                idx += 2 + length
            elif tag in [0x99, 0x8E]: 
                length = data[idx+1]
                idx += 2 + length
            else: idx += 1
        
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            return unpad(decrypt_3des(self.ks_enc, enc_data, iv))
        return b''

    def read_file_sfi(self, sfi):
        """Legge un file usando Short File Identifier (SFI) senza SELECT"""
        print(f"[*] Lettura Diretta SFI={sfi} (No Select)...")
        
        full_data = b''
        offset = 0
        chunk_size = 0xE0 
        
        while True:
            # Costruiamo P1 per SFI: 0x80 | SFI
            # P2 è l'offset
            p1 = 0x80 | sfi
            p2 = offset & 0xFF
            # Nota: P1 gestisce solo offset fino a 255 se usiamo SFI puro in alcuni casi,
            # ma ICAO standard usa READ BINARY con SFI in P1 (bit 8=1) e P2=Offset.
            # Se il file è grande, serve gestire offset > 255. 
            # ICAO 9303 Part 10: Se bit8 di P1 è 1, bit 1-5 sono SFI. P2 è offset.
            # Per offset > 255, bisogna usare SELECT. Ma DG1 e SOD sono piccoli o gestibili.
            # Proviamo con offset reset se necessario o assumiamo file piccoli per test.
            
            # Se offset > 255, questo metodo SFI semplice fallisce su alcuni chip.
            # Ma per DG1 (che è piccolo) dovrebbe funzionare.
            if offset > 255:
                print("    ! Attenzione: Offset > 255 richiede SELECT standard. Interrompo SFI.")
                break

            cmd = self.protect_apdu(0x00, 0xB0, p1, p2, None, le=chunk_size)
            resp, sw1, sw2 = self.conn.transmit(cmd)
            sw = (sw1 << 8) + sw2
            
            if sw != 0x9000:
                print(f"    -> Errore lettura chunk: {hex(sw)}")
                break
            
            chunk = self.unprotect_response(resp)
            full_data += chunk
            
            if len(chunk) < chunk_size:
                break
                
            offset += len(chunk)
            print(f"    -> Chunk letto: {len(chunk)} bytes")
            
        return full_data

# ==========================================
# 3. MAIN SCRIPT
# ==========================================
def main():
    print("--- ICAO 9303 SFI READER ---")
    
    # 1. Calcolo Chiavi
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc_mrz = derive_key(k_seed, 1)
    k_mac_mrz = derive_key(k_seed, 2)

    # 2. Connessione
    r = readers()
    if not r: sys.exit("No Reader")
    conn = r[0].createConnection()
    conn.connect()
    
    # 3. Auth BAC
    conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08])
    rnd_icc = bytes(resp)
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    
    plaintext = rnd_ifd + rnd_icc + k_ifd
    iv = bytes([0]*8)
    e_ifd = DES3.new(k_enc_mrz, DES3.MODE_CBC, iv).encrypt(plaintext)
    
    mac_data = pad(e_ifd)
    k_mac_a, k_mac_b = k_mac_mrz[:8], k_mac_mrz[8:16]
    step1 = DES.new(k_mac_a, DES.MODE_CBC, iv).encrypt(mac_data)[-8:]
    step2 = DES.new(k_mac_b, DES.MODE_ECB).decrypt(step1)
    m_ifd = DES.new(k_mac_a, DES.MODE_ECB).encrypt(step2)
    
    cmd_auth = [0x00, 0x82, 0x00, 0x00, 0x28] + list(e_ifd) + list(m_ifd) + [0x00]
    resp, sw1, sw2 = conn.transmit(cmd_auth)
    
    if (sw1<<8)+sw2 != 0x9000:
        print(f"❌ Auth Fallita: {hex((sw1<<8)+sw2)}")
        return

    # 4. Session Keys
    e_icc = bytes(resp)[:32]
    decrypted_resp = DES3.new(k_enc_mrz, DES3.MODE_CBC, bytes([0]*8)).decrypt(e_icc)
    k_icc = decrypted_resp[16:32]
    k_seed_sess = strxor(k_ifd, k_icc)
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    
    print("✅ Secure Messaging Attivo.")

    # 5. Download Files via SFI (SKIP SELECT)
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # DG1 -> SFI = 1
    data = sc.read_file_sfi(1)
    if data:
        with open("dg1.bin", "wb") as f: f.write(data)
        print(f"✅ DG1 Salvato ({len(data)} bytes)")
    else:
        print("❌ DG1 non letto.")

    data2 = sc.read_file_sfi(2)
    if data2:
        with open("dg2.bin", "wb") as f: f.write(data2)
        print(f"✅ DG2 Salvato ({len(data2)} bytes)")
    else:
        print("❌ DG2 non letto.")

    # SOD -> SFI = 29 (0x1D)
    data = sc.read_file_sfi(29)
    if data:
        with open("sod.bin", "wb") as f: f.write(data)
        print(f"✅ SOD Salvato ({len(data)} bytes)")
    else:
        print("❌ SOD non letto.")

if __name__ == "__main__":
    main()