import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# 1. I TUOI DATI
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# 2. IMPLEMENTAZIONE CRITTOGRAFICA
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

        # MAC Calculation
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        # Build Final APDU
        final_data = do_data + do_le + do_mac
        
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        if le is not None:
            apdu += [0x00] # Transport Le
            
        return apdu

    def unprotect_response(self, resp, sw1, sw2):
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
            elif tag in [0x99, 0x8E]: # Skip Status/MAC
                length = data[idx+1]
                idx += 2 + length
            else: idx += 1
        
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            return unpad(decrypt_3des(self.ks_enc, enc_data, iv))
        return b''

    def select_file_robust(self, file_id):
        """Prova a selezionare il file con due metodi diversi"""
        print(f"[*] Tentativo Selezione File {hex(file_id)}...")
        p1, p2 = (file_id >> 8) & 0xFF, file_id & 0xFF
        
        # TENTATIVO 1: Standard ICAO (P2=0C, No Le)
        print("    -> Metodo A (P2=0C, No Le)...")
        # Nota importante: salviamo SSC prima di provare, per ripristinarlo se fallisce!
        ssc_backup = self.ssc 
        
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x0C, bytes([p1, p2]), le=None)
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) + sw2
        
        if sw == 0x9000:
            print("    -> Metodo A SUCCESSO.")
            return True
            
        print(f"    -> Metodo A Fallito: {hex(sw)}")
        
        # TENTATIVO 2: Metodo FCI (P2=00, Le=00)
        # Se il primo ha fallito, dobbiamo "tornare indietro" col contatore SSC
        # altrimenti il prossimo comando avrà un MAC sbagliato rispetto a quello che si aspetta la carta.
        self.ssc = ssc_backup 
        
        print("    -> Metodo B (P2=00, Le=00)...")
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x00, bytes([p1, p2]), le=0x00)
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) + sw2
        
        if sw == 0x9000:
             print("    -> Metodo B SUCCESSO.")
             return True
        
        print(f"❌ Errore Selezione Totale: {hex(sw)}")
        return False

    def read_binary_loop(self):
        full_data = b''
        offset = 0
        chunk_size = 0xE0 
        while True:
            p1, p2 = (offset >> 8) & 0xFF, offset & 0xFF
            cmd = self.protect_apdu(0x00, 0xB0, p1, p2, None, le=chunk_size)
            resp, sw1, sw2 = self.conn.transmit(cmd)
            sw = (sw1 << 8) + sw2
            if sw != 0x9000: break
            
            chunk = self.unprotect_response(resp, sw1, sw2)
            full_data += chunk
            if len(chunk) < chunk_size: break
            offset += len(chunk)
            print(f"    -> Chunk letto: {len(chunk)} bytes")
        return full_data

# ==========================================
# 3. MAIN
# ==========================================
def main():
    print("="*60)
    print("   DEBUG SCAN: DUAL SELECT METHOD")
    print("="*60)

    # 1. SETUP CHIAVI
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc_mrz = derive_key(k_seed, 1)
    k_mac_mrz = derive_key(k_seed, 2)
    
    # 2. CONNESSIONE & AUTH
    r = readers()
    if not r: sys.exit("No Reader")
    conn = r[0].createConnection()
    conn.connect()
    
    conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08])
    if (sw1<<8)+sw2 != 0x9000: sys.exit("Challenge Fail")
    
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
        print(f"❌ Auth BAC Fallita: {hex((sw1<<8)+sw2)}")
        return

    # 3. CALCOLO SESSION KEYS
    e_icc = bytes(resp)[:32]
    decrypted_resp = DES3.new(k_enc_mrz, DES3.MODE_CBC, bytes([0]*8)).decrypt(e_icc)
    k_icc = decrypted_resp[16:32]
    k_seed_sess = strxor(k_ifd, k_icc)
    
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    
    print("✅ Secure Messaging Stabilito.")
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # 4. DOWNLOAD CON METODO ROBUSTO
    
    # DG1
    if sc.select_file_robust(0x0101):
        data = sc.read_binary_loop()
        with open("dg1.bin", "wb") as f: f.write(data)
        print(f"✅ DG1 Salvato ({len(data)} bytes)")
        
    # SOD
    if sc.select_file_robust(0x011D):
        data = sc.read_binary_loop()
        with open("sod.bin", "wb") as f: f.write(data)
        print(f"✅ SOD Salvato ({len(data)} bytes)")

if __name__ == "__main__":
    main()