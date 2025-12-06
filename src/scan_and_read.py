import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# 1. I TUOI DATI MRZ (MODIFICA QUI SE SERVE)
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# 2. IMPLEMENTAZIONE SECURE MESSAGING
# ==========================================

def pad(data):
    """Padding ISO 9797-1 Method 2 (80 00...)"""
    return data + b'\x80' + b'\x00' * (7 - (len(data) % 8))

def unpad(data):
    """Rimuove il padding"""
    idx = data.rfind(b'\x80')
    if idx == -1: return data
    return data[:idx]

def increment_ssc(ssc):
    """Incrementa il contatore SSC"""
    val = int.from_bytes(ssc, 'big')
    val += 1
    return val.to_bytes(8, 'big')

def encrypt_3des(key, data, iv=bytes([0]*8)):
    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(data)

def decrypt_3des(key, data, iv=bytes([0]*8)):
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(data)

def calc_mac(key, data):
    """Retail MAC (ISO 9797-1 Alg 3)"""
    ka, kb = key[:8], key[8:16]
    # Step 1: DES CBC Key A
    step1 = DES.new(ka, DES.MODE_CBC, bytes([0]*8)).encrypt(data)[-8:]
    # Step 2: DES ECB Decrypt Key B
    step2 = DES.new(kb, DES.MODE_ECB).decrypt(step1)
    # Step 3: DES ECB Encrypt Key A
    return DES.new(ka, DES.MODE_ECB).encrypt(step2)

class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc

    def protect_apdu(self, cla, ins, p1, p2, data=None, le=None):
        """Costruisce APDU protetto (Secure Messaging)"""
        self.ssc = increment_ssc(self.ssc) # 1. Incrementa SSC
        
        # Data Objects per SM
        # Header mascherato (CLA | 0x0C)
        do_cmd_header = pad(bytes([cla | 0x0C, ins, p1, p2])) 
        
        do_data = b''
        if data:
            # Encrypt Data (DO 87)
            padded_data = pad(data)
            iv = encrypt_3des(self.ks_enc, self.ssc) # IV dipende da SSC
            encrypted = encrypt_3des(self.ks_enc, padded_data, iv)
            # 0x87 + L + 0x01 + EncryptedData
            do_data = b'\x87' + bytes([len(encrypted)+1]) + b'\x01' + encrypted

        do_le = b''
        if le is not None:
            # DO 97 for Le
            do_le = b'\x97\x01' + bytes([le])

        # Calcolo MAC su: SSC + Header + Data + Le
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        # Costruzione comando finale
        final_data = do_data + do_le + do_mac
        
        return [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data) + [0x00]

    def unprotect_response(self, resp, sw1, sw2):
        """Decifra e verifica la risposta protetta"""
        self.ssc = increment_ssc(self.ssc) # Incrementa SSC anche per la risposta
        
        data = bytes(resp)
        # Parse Response Data Objects (DO)
        idx = 0
        enc_data = b''
        mac_bytes = b''
        
        # Parsing semplificato dei tag
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87: # Encrypted Data
                length = data[idx+1] 
                # Se length > 127 servirebbe logica ASN.1 length, ma per chunk piccoli ok
                enc_data = data[idx+3 : idx+2+length] # Skip 0x01
                idx += 2 + length
            elif tag == 0x99: # Processing Status
                length = data[idx+1]
                idx += 2 + length
            elif tag == 0x8E: # MAC
                length = data[idx+1]
                mac_bytes = data[idx+2 : idx+2+length]
                idx += 2 + length
            else:
                idx += 1
        
        # Qui dovremmo verificare il MAC, ma ci fidiamo per ora.
        
        decrypted = b''
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            decrypted = unpad(decrypt_3des(self.ks_enc, enc_data, iv))
            
        return decrypted

    def read_file(self, file_id):
        """Legge un intero file (DG o SOD) gestendo i chunk"""
        print(f"[*] Lettura File ID {hex(file_id)}...")
        
        # 1. Select File
        p1, p2 = (file_id >> 8) & 0xFF, file_id & 0xFF
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x0C, bytes([p1, p2]))
        
        # FIX: Unpack 3 valori
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) + sw2
        
        if sw != 0x9000 and sw != 0x6100: # Alcuni chip tornano 61xx (bytes available)
             # Ignoriamo errore se SW è OK
             if (sw >> 8) != 0x90 and (sw >> 8) != 0x61:
                print(f"Errore Selezione: {hex(sw)}")
                return None

        # 2. Read Binary Loop
        full_data = b''
        offset = 0
        chunk_size = 0xE0 # Leggiamo circa 224 byte alla volta
        
        while True:
            # P1/P2 sono l'offset
            p1_off = (offset >> 8) & 0xFF
            p2_off = offset & 0xFF
            
            # Read Binary Protected
            cmd = self.protect_apdu(0x00, 0xB0, p1_off, p2_off, None, le=chunk_size)
            
            # FIX: Unpack 3 valori
            resp, sw1, sw2 = self.conn.transmit(cmd)
            sw = (sw1 << 8) + sw2
            
            if sw != 0x9000:
                break
                
            decrypted_chunk = self.unprotect_response(resp, sw1, sw2)
            full_data += decrypted_chunk
            
            if len(decrypted_chunk) < chunk_size:
                break # Fine del file
            
            offset += len(decrypted_chunk)
            print(f"    -> Chunk letto (offset {offset})...")
            
        return full_data

# ==========================================
# 3. LOGICA PRINCIPALE
# ==========================================
def main():
    # --- A. Setup Chiavi MRZ ---
    print("[*] Calcolo chiavi BAC...")
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    c_enc, c_mac = bytes([0,0,0,1]), bytes([0,0,0,2])
    k_enc = hashlib.sha1(k_seed + c_enc).digest()[:16]
    k_mac = hashlib.sha1(k_seed + c_mac).digest()[:16]
    
    # --- B. Connessione e Auth ---
    r = readers()
    if not r: sys.exit("No Reader")
    conn = r[0].createConnection()
    conn.connect()
    
    # FIX: Unpack 3 valori per Select Applet
    conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    
    # FIX: Unpack 3 valori per Get Challenge
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08]) 
    if (sw1 << 8) + sw2 != 0x9000:
        print(f"Errore Get Challenge: {hex((sw1<<8)+sw2)}")
        return
        
    rnd_icc = bytes(resp)
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    
    plaintext = rnd_ifd + rnd_icc + k_ifd
    iv = bytes([0]*8)
    e_ifd = DES3.new(k_enc, DES3.MODE_CBC, iv).encrypt(plaintext)
    
    mac_data = pad(e_ifd)
    k_mac_a, k_mac_b = k_mac[:8], k_mac[8:16]
    mac_temp = DES.new(k_mac_a, DES.MODE_CBC, iv).encrypt(mac_data)[-8:]
    mac_temp = DES.new(k_mac_b, DES.MODE_ECB).decrypt(mac_temp)
    m_ifd = DES.new(k_mac_a, DES.MODE_ECB).encrypt(mac_temp)
    
    cmd_auth = [0x00, 0x82, 0x00, 0x00, 0x28] + list(e_ifd) + list(m_ifd) + [0x00]
    
    # FIX: Unpack 3 valori per Mutual Auth
    resp, sw1, sw2 = conn.transmit(cmd_auth)
    sw = (sw1 << 8) + sw2
    
    if sw != 0x9000:
        print(f"❌ Auth Fallita: {hex(sw)}")
        return

    # --- C. Calcolo Chiavi Sessione (KS) e SSC ---
    e_icc = bytes(resp)[:32]
    decrypted_resp = DES3.new(k_enc, DES3.MODE_CBC, bytes([0]*8)).decrypt(e_icc)
    k_icc = decrypted_resp[16:32]
    k_seed_session = strxor(k_ifd, k_icc)
    
    ks_enc = hashlib.sha1(k_seed_session + c_enc).digest()[:16]
    ks_mac = hashlib.sha1(k_seed_session + c_mac).digest()[:16]
    ssc = rnd_icc[-4:] + rnd_ifd[-4:] 
    
    print("✅ Secure Messaging Stabilito.")
    
    # --- D. SCARICAMENTO FILE ---
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # 1. SCARICA DG1 (ID: 0x0101)
    dg1_data = sc.read_file(0x0101)
    if dg1_data:
        # Rimuove il tag wrapper ASN.1 (Tag 61 + length) se presente all'inizio
        # Di solito il file inizia con 61 xx (Tag Application)
        # Salviamo tutto il blob per sicurezza, il parser ASN.1 se ne occupa
        with open("dg1.bin", "wb") as f: f.write(dg1_data)
        print(f"✅ DG1 salvato (dg1.bin): {len(dg1_data)} bytes")
    
    # 2. SCARICA SOD (ID: 0x011D)
    sod_data = sc.read_file(0x011D)
    if sod_data:
        # Anche qui, salviamo raw
        with open("sod.bin", "wb") as f: f.write(sod_data)
        print(f"✅ SOD salvato (sod.bin): {len(sod_data)} bytes")

    print("\nFatto! Ora controlla dg1.bin e sod.bin nella cartella.")

if __name__ == "__main__":
    main()