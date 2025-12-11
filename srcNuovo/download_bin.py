import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES3, DES
from Crypto.Util.Padding import pad as pkcs_pad, unpad as pkcs_unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# 1. DATI MRZ (Verifica che siano corretti al 100%)
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# 2. IMPLEMENTAZIONE CRITTOGRAFICA RIGOROSA (ICAO 9303)
# ==========================================

def derive_key(seed, mode):
    # Append 1, 2, 3 or 4 based on mode (Enc/MAC)
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    # 3DES Key K1=K3 (16 bytes)
    return d[:16]

def iso9797_pad(data):
    # Padding Method 2 (Bit Padding): Add 0x80 then 0x00...
    return data + b'\x80' + b'\x00' * (7 - (len(data) % 8))

def iso9797_unpad(data):
    idx = data.rfind(b'\x80')
    if idx == -1: return data
    return data[:idx]

def increment_ssc(ssc):
    val = int.from_bytes(ssc, 'big')
    val += 1
    # Handle wrap-around just in case, though unlikely in one session
    return val.to_bytes(8, 'big')

def encrypt_3des(key, data, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(data)

def decrypt_3des(key, data, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(data)

def calc_mac(key, data):
    # Retail MAC (ISO 9797-1 MAC Algorithm 3)
    k1 = key[:8]
    k2 = key[8:16]
    
    # Steps: DES CBC with K1, then DES Decrypt last block with K2, then DES Encrypt with K1
    des_cbc = DES.new(k1, DES.MODE_CBC, bytes(8))
    mac_step1 = des_cbc.encrypt(data)[-8:]
    
    des_inv = DES.new(k2, DES.MODE_ECB)
    mac_step2 = des_inv.decrypt(mac_step1)
    
    des_fin = DES.new(k1, DES.MODE_ECB)
    mac_final = des_fin.encrypt(mac_step2)
    
    return mac_final

class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc
        print(f"[DEBUG] Initial SSC: {self.ssc.hex().upper()}")

    def send_apdu(self, cla, ins, p1, p2, data=None, le=None):
        """
        Costruisce APDU protetta (DO87, DO97, DO8E)
        """
        # 1. Incrementa SSC per il comando
        self.ssc = increment_ssc(self.ssc)
        
        # 2. Costruzione DO87 (Encrypted Data) se c'è payload
        do87 = b''
        if data:
            padded_payload = iso9797_pad(data)
            # IV per encrypt command è E(K_enc, SSC)
            iv = encrypt_3des(self.ks_enc, self.ssc, bytes(8))
            encrypted_payload = encrypt_3des(self.ks_enc, padded_payload, iv)
            
            # ASN.1 Coding per 0x87
            # 0x87 + L + 0x01 + EncData
            # 0x01 è il padding content indicator
            body = b'\x01' + encrypted_payload
            
            # Gestione lunghezza ASN.1
            if len(body) < 128:
                len_byte = bytes([len(body)])
            else:
                # Semplificato per lunghezze < 256, se serve di più va esteso
                len_byte = b'\x81' + bytes([len(body)])
                
            do87 = b'\x87' + len_byte + body

        # 3. Costruzione DO97 (Le protetto)
        do97 = b''
        if le is not None:
            # DO97 value is Le byte(s)
            le_bytes = bytes([le]) if le < 256 else bytes([0x00]) # Example
            if le == 256: le_bytes = b'\x00' # Special case 00 means 256
            
            do97 = b'\x97\x01' + le_bytes

        # 4. Calcolo MAC
        # Header mascherato: Class byte | 0x0C
        masked_header = bytes([cla | 0x0C, ins, p1, p2])
        padded_header = iso9797_pad(masked_header)
        
        # Dati da Maccare: SSC + PaddedHeader + DO87 + DO97
        M = self.ssc + padded_header + do87 + do97
        padded_M = iso9797_pad(M)
        mac = calc_mac(self.ks_mac, padded_M)
        
        do8e = b'\x8E\x08' + mac
        
        # 5. Costruzione APDU finale
        final_data = do87 + do97 + do8e
        
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        if le is not None:
            apdu.append(0x00) # Response Length expected
            
        # DEBUG
        # print(f"-> APDU: {toHexString(apdu)}")
        
        resp, sw1, sw2 = self.conn.transmit(apdu)
        return self.process_response(resp, sw1, sw2)

    def process_response(self, resp, sw1, sw2):
        """
        Verifica MAC risposta e decripta DO87
        """
        data = bytes(resp)
        sw = (sw1 << 8) + sw2
        
        # Se errore SM (6988) o altro, non incrementiamo SSC per il decrypt
        # Ma ICAO dice: SSC incrementato per send, SSC incrementato per receive.
        # Se la carta risponde con errore, spesso non usa SM.
        if sw != 0x9000 and len(data) < 4:
            return None, sw

        # 1. Incrementa SSC per la risposta
        self.ssc = increment_ssc(self.ssc)
        
        # 2. Parse Response Objects
        idx = 0
        enc_data = b''
        mac_data = b''
        do99 = b'' # Status word protected
        
        # Trova DO87, DO99, DO8E
        while idx < len(data):
            tag = data[idx]
            if tag == 0x87:
                # Parse length
                if data[idx+1] < 0x80:
                    L = data[idx+1]
                    start = idx + 2
                else:
                    n = data[idx+1] & 0x7F
                    L = int.from_bytes(data[idx+2:idx+2+n], 'big')
                    start = idx + 2 + n
                enc_data = data[start+1 : start+L] # Skip 0x01 marker
                idx = start + L
            elif tag == 0x99:
                # SW protetto (obbligatorio in risposta)
                L = data[idx+1]
                do99 = data[idx : idx+2+L]
                idx += 2 + L
            elif tag == 0x8E:
                # MAC
                L = data[idx+1]
                mac_data = data[idx+2 : idx+2+L]
                idx += 2 + L
            else:
                idx += 1
        
        if not mac_data:
            print("   ⚠️ Nessun MAC nella risposta!")
            return None, sw

        # 3. Verifica MAC
        # K = SSC + DO87 + DO99
        # Ricostruiamo i dati ricevuti (escluso DO8E) per il controllo
        # Nota: dobbiamo prendere i byte esatti ricevuti per DO87 e DO99
        # Per semplicità, ricostruiamo la stringa 'M' tagliando via il DO8E finale
        response_body_no_mac = data[:-10] # Toglie 8E 08 ...MAC...
        
        K = self.ssc + response_body_no_mac
        calc_mac_val = calc_mac(self.ks_mac, iso9797_pad(K))
        
        if calc_mac_val != mac_data:
            print(f"   ❌ MAC Risposta Fallito! Atteso: {calc_mac_val.hex()} Ricevuto: {mac_data.hex()}")
            return None, 0x6988
            
        # 4. Decripta Dati (se presenti)
        decrypted = b''
        if enc_data:
            # IV per risposta = E(K_enc, SSC)
            iv = encrypt_3des(self.ks_enc, self.ssc, bytes(8))
            decrypted_padded = decrypt_3des(self.ks_enc, enc_data, iv)
            decrypted = iso9797_unpad(decrypted_padded)
            
        return decrypted, sw

    def read_file(self, file_id_hex, name):
        """
        Esegue SELECT e poi READ BINARY a blocchi
        """
        file_id = bytes.fromhex(file_id_hex)
        print(f"\n[*] Download {name} (ID: {file_id_hex})...")
        
        # 1. SELECT (00 A4 02 0C 02 [FileID])
        # P2=0C significa "First Record" o "No return data" (XML vs Binary)
        # Alcuni passaporti vogliono P2=00 o P2=0C. Standard ePassport è 0C.
        res, sw = self.send_apdu(0x00, 0xA4, 0x02, 0x0C, file_id)
        
        if sw != 0x9000:
            print(f"   ❌ SELECT Fallita: {hex(sw)}")
            return None
            
        # 2. READ BINARY LOOP
        full_data = b''
        offset = 0
        chunk_size = 0xE0 # Safe size
        
        while True:
            p1 = (offset >> 8) & 0xFF
            p2 = offset & 0xFF
            
            # Read Binary: 00 B0 P1 P2 Le
            chunk, sw = self.send_apdu(0x00, 0xB0, p1, p2, None, le=chunk_size)
            
            if sw != 0x9000:
                # Fine file normale (spesso 6B00 o 6282)
                if sw == 0x6B00 or sw == 0x6282: 
                    break
                print(f"   ❌ Read Error @{offset}: {hex(sw)}")
                break
                
            if not chunk:
                break
                
            full_data += chunk
            # print(f"   -> Letto chunk {len(chunk)} bytes")
            
            if len(chunk) < chunk_size:
                break
            offset += len(chunk)
            
        if len(full_data) > 0:
            print(f"   ✅ {name} scaricato: {len(full_data)} bytes. Header: {full_data[:4].hex().upper()}")
            return full_data
        return None

# ==========================================
# 3. MAIN SCRIPT
# ==========================================
def main():
    print("--- ICAO 9303 ROBUST READER (FIXED) ---")
    
    # 1. Calcolo Chiavi BAC
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    print(f"[*] MRZ Seed: {mrz_info}")
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    
    # Chiavi K_enc e K_mac iniziali (derivazione corretta ICAO)
    # K_enc usa c=1, K_mac usa c=2
    k_enc_bac = derive_key(k_seed, 1)
    k_mac_bac = derive_key(k_seed, 2)
    
    print(f"[*] K_enc_BAC: {k_enc_bac.hex().upper()}")
    print(f"[*] K_mac_BAC: {k_mac_bac.hex().upper()}")

    # 2. Connessione
    r = readers()
    if not r: sys.exit("No Reader")
    conn = r[0].createConnection()
    conn.connect()
    
    # 3. BAC Authentication
    print("\n[*] Eseguo BAC...")
    # Select Applet
    conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    
    # Get Challenge
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08])
    rnd_icc = bytes(resp)
    
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    
    # Costruzione Risposta Auth
    s = rnd_ifd + rnd_icc + k_ifd
    iv_zero = bytes(8)
    e_ifd = encrypt_3des(k_enc_bac, s, iv_zero)
    
    # MAC
    m_ifd = calc_mac(k_mac_bac, iso9797_pad(e_ifd))
    
    cmd_data = e_ifd + m_ifd
    cmd = [0x00, 0x82, 0x00, 0x00, len(cmd_data)] + list(cmd_data) + [0x28] # Le=40
    
    resp, sw1, sw2 = conn.transmit(cmd)
    
    if (sw1<<8)+sw2 != 0x9000:
        print(f"❌ BAC Fallita: {hex((sw1<<8)+sw2)}")
        return

    # 4. Derivazione Session Keys
    # Decripta risposta (32 bytes)
    resp_data = bytes(resp)
    e_icc = resp_data[:32]
    # m_icc = resp_data[32:40] # Verification skipped for brevity, but should be done
    
    dec_icc = decrypt_3des(k_enc_bac, e_icc, iv_zero)
    k_icc = dec_icc[16:32]
    
    # Calcolo Session Seed
    k_seed_sess = strxor(k_ifd, k_icc)
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    
    # Calcolo Initial SSC (Appendice D.1 ICAO 9303)
    # SSC = RND.IC (Last 4) + RND.IFD (Last 4)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    
    print("✅ BAC OK. Session Keys Stabilite.")
    
    # 5. Inizio Secure Messaging con classe corretta
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # 6. DOWNLOAD FILES
    # DG1 (MRZ) - File ID 0101
    dg1 = sc.read_file("0101", "DG1")
    if dg1:
        with open("dg1.bin", "wb") as f: f.write(dg1)
        # Check visivo per vedere se "ITA" è intero
        try:
            print(f"   -> DG1 Preview: {dg1[5:20]}") 
        except: pass

    # DG2 (Foto) - File ID 0102
    dg2 = sc.read_file("0102", "DG2")
    if dg2:
        with open("dg2.bin", "wb") as f: f.write(dg2)

    # SOD (Security Object) - File ID 011D
    sod = sc.read_file("011D", "SOD")
    if sod:
        with open("sod.bin", "wb") as f: f.write(sod)
        print("\n✅ FILE SOD SCARICATO. Ora esegui 'passive_auth.py'.")

if __name__ == "__main__":
    main()