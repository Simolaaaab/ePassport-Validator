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
# 2. IMPLEMENTAZIONE CRITTOGRAFICA ICAO 9303
# ==========================================

def derive_key(seed, mode):
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    return d[:8] + d[8:16]

def pad(data):
    """ISO 9797-1 Method 2 Padding (Add 0x80 then 0x00...)"""
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
    """Retail MAC"""
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

    def protect_apdu(self, cla, ins, p1, p2, data=None, expected_le=None):
        """
        Costruisce APDU protetto secondo ICAO 9303.
        expected_le: Se None, NON aggiunge DO97 (per Select File).
                     Se int (es. 0 o 256), aggiunge DO97 (per Read Binary).
        """
        self.ssc = increment_ssc(self.ssc) 
        
        # 1. Costruzione DO 87 (Encrypted Data)
        do_data = b''
        if data:
            padded_data = pad(data)
            iv = encrypt_3des(self.ks_enc, self.ssc) 
            encrypted = encrypt_3des(self.ks_enc, padded_data, iv)
            # Tag 0x87 + Length + 0x01 (Indicator) + Data
            do_data = b'\x87' + bytes([len(encrypted)+1]) + b'\x01' + encrypted

        # 2. Costruzione DO 97 (Expected Length - Le)
        # CRUCIALE: Se expected_le è None, questo oggetto NON deve esistere.
        do_le = b''
        if expected_le is not None:
            # Tag 0x97 + Length (1) + Value
            # Nota: Le=00 in APDU significa 256 byte, ma nel DO97 si mette il valore esatto se si vuole,
            # oppure 00 per "max". Usiamo 00 per standard.
            do_le = b'\x97\x01' + bytes([expected_le if expected_le > 0 else 0])

        # 3. Costruzione Header Mascherato per il MAC
        # L'header deve essere paddato
        masked_header = bytes([cla | 0x0C, ins, p1, p2])
        do_cmd_header = pad(masked_header) 

        # 4. Calcolo MAC
        # M = SSC + Header(Padded) + DO87 + DO97
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        # 5. Costruzione APDU Finale
        # Data Field = DO87 + DO97 + DO8E
        final_data = do_data + do_le + do_mac
        
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        
        # 6. Aggiunta Transport Le (il byte 00 finale fisico)
        # Solo se c'è un DO97 (cioè ci aspettiamo risposta)
        if expected_le is not None:
            apdu += [0x00]
            
        return apdu

    def unprotect_response(self, resp, sw1, sw2):
        self.ssc = increment_ssc(self.ssc)
        data = bytes(resp)
        idx = 0
        enc_data = b''
        
        # Parsing semplificato DO
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87: 
                length = data[idx+1]
                # Gestione length estesa ASN.1 se necessario (qui semplifichiamo < 128)
                enc_data = data[idx+3 : idx+2+length]
                idx += 2 + length
            elif tag == 0x99: # SW
                length = data[idx+1]
                idx += 2 + length
            elif tag == 0x8E: # MAC
                length = data[idx+1]
                idx += 2 + length
            else:
                idx += 1
        
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            return unpad(decrypt_3des(self.ks_enc, enc_data, iv))
        return b''

    def read_entire_file(self, file_id):
        print(f"[*] Lettura File {hex(file_id)}...")
        
        # STEP 1: SELECT FILE
        # Importante: expected_le=None perché SELECT non ritorna dati utente
        p1, p2 = (file_id >> 8) & 0xFF, file_id & 0xFF
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x0C, bytes([p1, p2]), expected_le=None)
        
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) + sw2
        
        if sw != 0x9000:
            print(f"    ❌ Select Fallita: {hex(sw)}")
            return None
        print("    ✅ Select OK")

        # STEP 2: READ BINARY
        full_data = b''
        offset = 0
        chunk_size = 0xE0 # Leggiamo a blocchi
        
        while True:
            p1_off = (offset >> 8) & 0xFF
            p2_off = offset & 0xFF
            
            # Importante: expected_le=0 per dire "dammi dati"
            cmd = self.protect_apdu(0x00, 0xB0, p1_off, p2_off, None, expected_le=0x00)
            
            resp, sw1, sw2 = self.conn.transmit(cmd)
            sw = (sw1 << 8) + sw2
            
            if sw != 0x9000:
                break
                
            chunk = self.unprotect_response(resp, sw1, sw2)
            full_data += chunk
            
            # Se il chunk è vuoto o più piccolo del richiesto, abbiamo finito
            if not chunk or len(chunk) < chunk_size:
                break
                
            offset += len(chunk)
            print(f"    -> Chunk letto: {len(chunk)} bytes")
            
        return full_data

# ==========================================
# 3. MAIN SCRIPT
# ==========================================
def main():
    print("--- START ICAO 9303 READER ---")
    
    # 1. Calcolo Chiavi BAC (Semplificato)
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc_mrz = derive_key(k_seed, 1)
    k_mac_mrz = derive_key(k_seed, 2)

    # 2. Connessione
    r = readers()
    if not r: sys.exit("Nessun lettore")
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

    # 4. Calcolo Session Keys
    e_icc = bytes(resp)[:32]
    decrypted_resp = DES3.new(k_enc_mrz, DES3.MODE_CBC, bytes([0]*8)).decrypt(e_icc)
    k_icc = decrypted_resp[16:32]
    k_seed_sess = strxor(k_ifd, k_icc)
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    
    print("✅ Autenticazione BAC Completata.")

    # 5. Download Files
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # DG1
    data = sc.read_entire_file(0x0101)
    if data:
        with open("dg1.bin", "wb") as f: f.write(data)
        print(f"✅ DG1 Salvato ({len(data)} bytes)")

    # SOD
    data = sc.read_entire_file(0x011D)
    if data:
        with open("sod.bin", "wb") as f: f.write(data)
        print(f"✅ SOD Salvato ({len(data)} bytes)")

if __name__ == "__main__":
    main()