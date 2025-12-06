import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
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
# 2. FUNZIONI CRITTOGRAFICHE DI BASE
# ==========================================

def derive_key(seed, mode):
    """Deriva le chiavi (Kenc/Kmac) dal Seed usando SHA-1"""
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    return d[:8] + d[8:16]

def pad(data):
    """Padding ISO per il MAC (80 00...)"""
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
    step1 = DES.new(ka, DES.MODE_CBC, bytes([0]*8)).encrypt(data)[-8:]
    step2 = DES.new(kb, DES.MODE_ECB).decrypt(step1)
    return DES.new(ka, DES.MODE_ECB).encrypt(step2)

# ==========================================
# 3. CLASSE SECURE CHANNEL (Per leggere i file)
# ==========================================

class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc

    def protect_apdu(self, cla, ins, p1, p2, data=None, le=None):
        """Costruisce APDU protetto (Secure Messaging)"""
        self.ssc = increment_ssc(self.ssc) 
        
        # Header mascherato (CLA | 0x0C)
        do_cmd_header = pad(bytes([cla | 0x0C, ins, p1, p2])) 
        
        do_data = b''
        if data:
            padded_data = pad(data)
            iv = encrypt_3des(self.ks_enc, self.ssc) 
            encrypted = encrypt_3des(self.ks_enc, padded_data, iv)
            # DO 87: 0x87 + L + 0x01 + EncryptedData
            do_data = b'\x87' + bytes([len(encrypted)+1]) + b'\x01' + encrypted

        do_le = b''
        if le is not None:
            # DO 97: 0x97 + L + Le
            do_le = b'\x97\x01' + bytes([le])

        # Calcolo MAC
        M = self.ssc + do_cmd_header + do_data + do_le
        mac = calc_mac(self.ks_mac, pad(M))
        do_mac = b'\x8E\x08' + mac
        
        # Costruzione comando finale
        final_data = do_data + do_le + do_mac
        
        # FIX FONDAMENTALE PER ERRORE 0x6988:
        # Aggiungiamo il byte finale [0x00] SOLO se ci aspettiamo una risposta (le != None).
        # Per il comando "Select File", le è None, quindi NON mettiamo 0x00.
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        if le is not None:
            apdu += [0x00] 
            
        return apdu

    def unprotect_response(self, resp, sw1, sw2):
        """Decifra la risposta"""
        self.ssc = increment_ssc(self.ssc)
        
        data = bytes(resp)
        idx = 0
        enc_data = b''
        
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87: # Encrypted Data
                length = data[idx+1] 
                enc_data = data[idx+3 : idx+2+length] # Skip 0x01
                idx += 2 + length
            elif tag == 0x99: # Status Word
                length = data[idx+1]
                idx += 2 + length
            elif tag == 0x8E: # MAC
                length = data[idx+1]
                idx += 2 + length
            else:
                idx += 1
        
        decrypted = b''
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc)
            decrypted = unpad(decrypt_3des(self.ks_enc, enc_data, iv))
            
        return decrypted

    def read_file(self, file_id):
        print(f"[*] Lettura File ID {hex(file_id)}...")
        
        # 1. Select File (Nota: le=None qui! Questo evita l'errore 0x6988)
        p1, p2 = (file_id >> 8) & 0xFF, file_id & 0xFF
        cmd = self.protect_apdu(0x00, 0xA4, 0x02, 0x0C, bytes([p1, p2]), le=None)
        
        resp, sw1, sw2 = self.conn.transmit(cmd)
        sw = (sw1 << 8) + sw2
        
        if sw != 0x9000:
             print(f"❌ Errore Selezione: {hex(sw)}")
             return None

        # 2. Read Binary Loop
        full_data = b''
        offset = 0
        chunk_size = 0xE0 
        
        while True:
            p1_off = (offset >> 8) & 0xFF
            p2_off = offset & 0xFF
            
            # Read Binary (Qui le è presente!)
            cmd = self.protect_apdu(0x00, 0xB0, p1_off, p2_off, None, le=chunk_size)
            
            resp, sw1, sw2 = self.conn.transmit(cmd)
            sw = (sw1 << 8) + sw2
            
            if sw != 0x9000:
                break
                
            decrypted_chunk = self.unprotect_response(resp, sw1, sw2)
            full_data += decrypted_chunk
            
            if len(decrypted_chunk) < chunk_size:
                break 
            
            offset += len(decrypted_chunk)
            print(f"    -> Chunk letto (offset {offset})...")
            
        return full_data

def send_apdu(connection, apdu):
    resp, sw1, sw2 = connection.transmit(apdu)
    sw = (sw1 << 8) + sw2
    return resp, sw

# ==========================================
# 4. MAIN (LA TUA LOGICA + IL DOWNLOAD)
# ==========================================

def main():
    print("="*60)
    print("   FUSIONE SCRIPT: CALCOLO CHIAVI + DOWNLOAD FILE")
    print("="*60)

    # --- FASE 1: Calcolo Chiavi MRZ (Access Keys) ---
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    k_seed_mrz = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc = derive_key(k_seed_mrz, 1)
    k_mac = derive_key(k_seed_mrz, 2)
    
    print(f"[*] Access Keys (da MRZ):")
    print(f"    K_enc: {toHexString(list(k_enc))}")
    print(f"    K_mac: {toHexString(list(k_mac))}")

    # --- FASE 2: Connessione ---
    r = readers()
    if not r: sys.exit("Nessun lettore")
    connection = r[0].createConnection()
    connection.connect()

    # --- FASE 3: Handshake BAC ---
    # Select Applet
    send_apdu(connection, [0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    
    # Get Challenge (Ricevi RND.ICC)
    resp, _ = send_apdu(connection, [0x00, 0x84, 0x00, 0x00, 0x08])
    rnd_icc = bytes(resp) # 8 bytes

    # Genera i nostri segreti
    rnd_ifd = get_random_bytes(8)
    k_ifd   = get_random_bytes(16)
    
    # Prepara pacchetto cifrato
    plaintext = rnd_ifd + rnd_icc + k_ifd
    iv = bytes([0]*8)
    e_ifd = DES3.new(k_enc, DES3.MODE_CBC, iv).encrypt(plaintext)
    
    # Calcolo MAC
    mac_input = pad(e_ifd)
    k_mac_a, k_mac_b = k_mac[:8], k_mac[8:16]
    mac_temp = DES.new(k_mac_a, DES.MODE_CBC, iv).encrypt(mac_input)[-8:]
    mac_temp = DES.new(k_mac_b, DES.MODE_ECB).decrypt(mac_temp)
    m_ifd    = DES.new(k_mac_a, DES.MODE_ECB).encrypt(mac_temp)

    # INVIA MUTUAL AUTHENTICATE
    cmd = [0x00, 0x82, 0x00, 0x00, 0x28] + list(e_ifd) + list(m_ifd) + [0x00]
    resp_list, sw = send_apdu(connection, cmd) # Corretto per prendere 2 valori qui

    if sw != 0x9000:
        print(f"❌ Auth Fallita con codice {hex(sw)}")
        sys.exit(1)
        
    print("✅ Auth OK! Ora calcoliamo le Session Keys (Metodo Tuo)...")

    # --- DECIFRATURA RISPOSTA (IL TUO CODICE) ---
    resp_data = bytes(resp_list)
    if len(resp_data) < 32:
        print("Errore: Risposta troppo corta dal passaporto.")
        sys.exit()

    e_icc = resp_data[:32] # La parte cifrata
    
    # Decifriamo la risposta usando K_enc (MRZ)
    iv_resp = bytes([0]*8) 
    decryptor = DES3.new(k_enc, DES3.MODE_CBC, iv_resp)
    decrypted_response = decryptor.decrypt(e_icc)
    
    # Troviamo K.ICC
    found_k_icc = decrypted_response[16:32]
    
    # --- CALCOLO CHIAVI SESSIONE FINALI ---
    # K_seed = K_IFD XOR K_ICC
    k_seed_session = strxor(k_ifd, found_k_icc)
    
    # Derive KS
    ks_enc = derive_key(k_seed_session, 1)
    ks_mac = derive_key(k_seed_session, 2)
    
    # Calcolo SSC
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]

    print("-" * 50)
    print("🔑 CHIAVI DI SESSIONE ATTIVE:")
    print(f"KS_enc: {toHexString(list(ks_enc))}")
    print(f"KS_mac: {toHexString(list(ks_mac))}")
    print(f"SSC:    {toHexString(list(ssc))}")
    print("-" * 50)
    
    # ==========================================================
    # ORA USIAMO QUESTE CHIAVI PER SCARICARE I FILE!
    # ==========================================================
    
    print("\n⬇️ AVVIO DOWNLOAD FILE CON SECURE MESSAGING...")
    
    # Inizializziamo il canale sicuro con le chiavi appena calcolate
    sc = SecureChannel(connection, ks_enc, ks_mac, ssc)
    
    # SCARICA DG1 (ID: 0x0101)
    dg1_data = sc.read_file(0x0101)
    if dg1_data:
        with open("dg1.bin", "wb") as f: f.write(dg1_data)
        print(f"✅ DG1 salvato (dg1.bin): {len(dg1_data)} bytes")
    
    # SCARICA SOD (ID: 0x011D)
    sod_data = sc.read_file(0x011D)
    if sod_data:
        with open("sod.bin", "wb") as f: f.write(sod_data)
        print(f"✅ SOD salvato (sod.bin): {len(sod_data)} bytes")

    print("\n🎉 COMPLETATO! Controlla la cartella.")

if __name__ == "__main__":
    main()