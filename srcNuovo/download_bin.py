import hashlib
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import DES3, DES
from Crypto.Util.Padding import pad as pkcs_pad, unpad as pkcs_unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# ==========================================
# DATI MRZ
# ==========================================
PASSPORT_NO = "YC6096319"
CHECK_NO    = "6"
DOB         = "700510"
CHECK_DOB   = "7"
EXPIRY      = "340714"
CHECK_EXP   = "9"

# ==========================================
# FUNZIONI CRITTOGRAFICHE
# ==========================================

def derive_key(seed, mode):
    """Deriva chiavi secondo ICAO 9303"""
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    return d[:16]

def iso9797_pad(data):
    """ISO 9797 Padding Method 2"""
    return data + b'\x80' + b'\x00' * (7 - (len(data) % 8))

def iso9797_unpad(data):
    """Rimuove ISO 9797 padding"""
    idx = data.rfind(b'\x80')
    if idx == -1: 
        return data
    return data[:idx]

def increment_ssc(ssc):
    """Incrementa Send Sequence Counter"""
    val = int.from_bytes(ssc, 'big')
    val += 1
    return val.to_bytes(8, 'big')

def encrypt_3des(key, data, iv):
    """3DES CBC encryption"""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(data)

def decrypt_3des(key, data, iv):
    """3DES CBC decryption"""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(data)

def calc_mac(key, data):
    """Retail MAC (ISO 9797-1 MAC Algorithm 3)"""
    k1 = key[:8]
    k2 = key[8:16]
    
    des_cbc = DES.new(k1, DES.MODE_CBC, bytes(8))
    mac_step1 = des_cbc.encrypt(data)[-8:]
    
    des_inv = DES.new(k2, DES.MODE_ECB)
    mac_step2 = des_inv.decrypt(mac_step1)
    
    des_fin = DES.new(k1, DES.MODE_ECB)
    mac_final = des_fin.encrypt(mac_step2)
    
    return mac_final

def parse_asn1_length(data, offset):
    """Parse lunghezza ASN.1"""
    if data[offset] < 0x80:
        return data[offset], offset + 1
    elif data[offset] == 0x81:
        return data[offset + 1], offset + 2
    elif data[offset] == 0x82:
        return (data[offset + 1] << 8) | data[offset + 2], offset + 3
    else:
        raise ValueError(f"Lunghezza ASN.1 non supportata: {hex(data[offset])}")

def encode_asn1_length(length):
    """Codifica lunghezza ASN.1"""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return b'\x81' + bytes([length])
    else:
        return b'\x82' + bytes([length >> 8, length & 0xFF])

# ==========================================
# SECURE MESSAGING
# ==========================================

class SecureChannel:
    def __init__(self, connection, ks_enc, ks_mac, ssc):
        self.conn = connection
        self.ks_enc = ks_enc
        self.ks_mac = ks_mac
        self.ssc = ssc
        print(f"[DEBUG] SSC iniziale: {self.ssc.hex().upper()}")

    def send_apdu(self, cla, ins, p1, p2, data=None, le=None):
        """Invia APDU protetto con Secure Messaging"""
        # Incrementa SSC
        self.ssc = increment_ssc(self.ssc)
        print(f"[DEBUG] SSC comando: {self.ssc.hex().upper()}")
        
        # Costruisci DO87 (dati cifrati)
        do87 = b''
        if data:
            padded_payload = iso9797_pad(data)
            iv = encrypt_3des(self.ks_enc, self.ssc, bytes(8))
            encrypted_payload = encrypt_3des(self.ks_enc, padded_payload, iv)
            
            body = b'\x01' + encrypted_payload
            do87 = b'\x87' + encode_asn1_length(len(body)) + body
            print(f"[DEBUG] DO87: {do87.hex().upper()}")

        # Costruisci DO97 (Le protetto)
        do97 = b''
        if le is not None:
            le_bytes = bytes([le]) if le < 256 else b'\x00'
            do97 = b'\x97\x01' + le_bytes
            print(f"[DEBUG] DO97: {do97.hex().upper()}")

        # Calcola MAC
        masked_header = bytes([cla | 0x0C, ins, p1, p2])
        padded_header = iso9797_pad(masked_header)
        
        M = self.ssc + padded_header + do87 + do97
        padded_M = iso9797_pad(M)
        mac = calc_mac(self.ks_mac, padded_M)
        
        do8e = b'\x8E\x08' + mac
        print(f"[DEBUG] MAC calcolato: {mac.hex().upper()}")
        
        # Costruisci APDU finale
        final_data = do87 + do97 + do8e
        apdu = [cla | 0x0C, ins, p1, p2, len(final_data)] + list(final_data)
        
        if le is not None:
            apdu.append(0x00)
            
        print(f"[DEBUG] APDU inviato: {toHexString(apdu)}")
        
        resp, sw1, sw2 = self.conn.transmit(apdu)
        return self.process_response(resp, sw1, sw2)

    def process_response(self, resp, sw1, sw2):
        """Processa risposta con Secure Messaging"""
        data = bytes(resp)
        sw = (sw1 << 8) + sw2
        
        print(f"[DEBUG] Risposta ricevuta: {data.hex().upper()} SW={hex(sw)}")
        
        if sw != 0x9000:
            return None, sw

        # Incrementa SSC per risposta
        self.ssc = increment_ssc(self.ssc)
        print(f"[DEBUG] SSC risposta: {self.ssc.hex().upper()}")
        
        # Parse risposta
        enc_data = b''
        mac_data = b''
        do99 = b''
        
        idx = 0
        while idx < len(data):
            tag = data[idx]
            
            if tag == 0x87:
                # DO87 - Dati cifrati
                length, idx = parse_asn1_length(data, idx + 1)
                enc_data = data[idx + 1 : idx + length]  # Salta 0x01
                idx += length
                print(f"[DEBUG] DO87 trovato, lunghezza: {length}")
                
            elif tag == 0x99:
                # DO99 - Status word
                length = data[idx + 1]
                do99 = data[idx : idx + 2 + length]
                idx += 2 + length
                print(f"[DEBUG] DO99 trovato")
                
            elif tag == 0x8E:
                # DO8E - MAC
                length = data[idx + 1]
                mac_data = data[idx + 2 : idx + 2 + length]
                idx += 2 + length
                print(f"[DEBUG] DO8E trovato, MAC: {mac_data.hex().upper()}")
            else:
                idx += 1
        
        if not mac_data:
            print("   ⚠️ Nessun MAC nella risposta!")
            return None, sw

        # Verifica MAC
        # Ricostruisci dati senza DO8E
        response_body_no_mac = data[:-10]  # Rimuovi 8E 08 + 8 byte MAC
        
        K = self.ssc + response_body_no_mac
        calc_mac_val = calc_mac(self.ks_mac, iso9797_pad(K))
        
        print(f"[DEBUG] MAC calcolato: {calc_mac_val.hex().upper()}")
        print(f"[DEBUG] MAC ricevuto:  {mac_data.hex().upper()}")
        
        if calc_mac_val != mac_data:
            print(f"   ❌ MAC non corrisponde!")
            return None, 0x6988
            
        # Decifra dati
        decrypted = b''
        if enc_data:
            iv = encrypt_3des(self.ks_enc, self.ssc, bytes(8))
            decrypted_padded = decrypt_3des(self.ks_enc, enc_data, iv)
            decrypted = iso9797_unpad(decrypted_padded)
            print(f"[DEBUG] Dati decifrati: {len(decrypted)} bytes")
            
        return decrypted, sw

    def read_file(self, file_id_hex, name):
        """Legge file dal passaporto"""
        file_id = bytes.fromhex(file_id_hex)
        print(f"\n[*] Download {name} (ID: {file_id_hex})...")
        
        # SELECT con P2=0C (standard ICAO)
        res, sw = self.send_apdu(0x00, 0xA4, 0x02, 0x0C, file_id)
        
        if sw != 0x9000:
            print(f"   ❌ SELECT fallita: {hex(sw)}")
            # Prova con P2=00
            print(f"   → Riprovo con P2=00...")
            res, sw = self.send_apdu(0x00, 0xA4, 0x02, 0x00, file_id)
            if sw != 0x9000:
                print(f"   ❌ SELECT fallita anche con P2=00: {hex(sw)}")
                return None
            
        print(f"   ✅ SELECT riuscito")
        
        # READ BINARY
        full_data = b''
        offset = 0
        chunk_size = 0xE0
        
        while True:
            p1 = (offset >> 8) & 0xFF
            p2 = offset & 0xFF
            
            chunk, sw = self.send_apdu(0x00, 0xB0, p1, p2, None, le=chunk_size)
            
            if sw == 0x6B00 or sw == 0x6282:
                # Fine file
                break
                
            if sw != 0x9000:
                print(f"   ❌ Errore lettura @{offset}: {hex(sw)}")
                break
                
            if not chunk:
                break
                
            full_data += chunk
            print(f"   → Letti {len(chunk)} bytes (totale: {len(full_data)})")
            
            if len(chunk) < chunk_size:
                break
                
            offset += len(chunk)
            
        if len(full_data) > 0:
            print(f"   ✅ {name}: {len(full_data)} bytes")
            print(f"   → Header: {full_data[:min(16, len(full_data))].hex().upper()}")
            return full_data
            
        return None

# ==========================================
# MAIN
# ==========================================

def main():
    print("=" * 60)
    print("ICAO 9303 PASSPORT READER - VERSIONE CORRETTA")
    print("=" * 60)
    
    # Calcola chiavi BAC
    mrz_info = f"{PASSPORT_NO}{CHECK_NO}{DOB}{CHECK_DOB}{EXPIRY}{CHECK_EXP}"
    print(f"\n[*] MRZ Info: {mrz_info}")
    
    k_seed = hashlib.sha1(mrz_info.encode('utf-8')).digest()[:16]
    k_enc_bac = derive_key(k_seed, 1)
    k_mac_bac = derive_key(k_seed, 2)
    
    print(f"[*] K_enc_BAC: {k_enc_bac.hex().upper()}")
    print(f"[*] K_mac_BAC: {k_mac_bac.hex().upper()}")

    # Connessione
    r = readers()
    if not r:
        sys.exit("❌ Nessun lettore trovato")
    
    print(f"\n[*] Lettore: {r[0]}")
    conn = r[0].createConnection()
    conn.connect()
    
    # BAC Authentication
    print("\n" + "=" * 60)
    print("BASIC ACCESS CONTROL")
    print("=" * 60)
    
    # Select eMRTD Application
    print("\n[*] Select eMRTD Application...")
    resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07, 
                                     0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
    if (sw1 << 8) + sw2 != 0x9000:
        sys.exit(f"❌ Select Application fallito: {hex((sw1<<8)+sw2)}")
    
    # Get Challenge
    print("[*] Get Challenge...")
    resp, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, 0x08])
    if (sw1 << 8) + sw2 != 0x9000:
        sys.exit(f"❌ Get Challenge fallito: {hex((sw1<<8)+sw2)}")
    
    rnd_icc = bytes(resp)
    print(f"[*] RND.ICC: {rnd_icc.hex().upper()}")
    
    # External Authenticate
    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    
    print(f"[*] RND.IFD: {rnd_ifd.hex().upper()}")
    print(f"[*] K.IFD: {k_ifd.hex().upper()}")
    
    s = rnd_ifd + rnd_icc + k_ifd
    iv_zero = bytes(8)
    e_ifd = encrypt_3des(k_enc_bac, s, iv_zero)
    m_ifd = calc_mac(k_mac_bac, iso9797_pad(e_ifd))
    
    cmd_data = e_ifd + m_ifd
    cmd = [0x00, 0x82, 0x00, 0x00, len(cmd_data)] + list(cmd_data) + [0x28]
    
    print("[*] External Authenticate...")
    resp, sw1, sw2 = conn.transmit(cmd)
    
    if (sw1 << 8) + sw2 != 0x9000:
        sys.exit(f"❌ BAC fallito: {hex((sw1<<8)+sw2)}")

    # Deriva Session Keys
    resp_data = bytes(resp)
    e_icc = resp_data[:32]
    dec_icc = decrypt_3des(k_enc_bac, e_icc, iv_zero)
    k_icc = dec_icc[16:32]
    
    k_seed_sess = strxor(k_ifd, k_icc)
    ks_enc = derive_key(k_seed_sess, 1)
    ks_mac = derive_key(k_seed_sess, 2)
    
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]
    
    print("\n✅ BAC COMPLETATO")
    print(f"[*] KS_Enc: {ks_enc.hex().upper()}")
    print(f"[*] KS_Mac: {ks_mac.hex().upper()}")
    print(f"[*] SSC: {ssc.hex().upper()}")
    
    # Secure Messaging
    print("\n" + "=" * 60)
    print("LETTURA DATAGROUPS")
    print("=" * 60)
    
    sc = SecureChannel(conn, ks_enc, ks_mac, ssc)
    
    # Leggi files
    files_to_read = [
        ("0101", "DG1 (MRZ)", "dg1.bin"),
        ("0102", "DG2 (Photo)", "dg2.bin"),
        ("011D", "SOD", "sod.bin")
    ]
    
    for file_id, name, filename in files_to_read:
        data = sc.read_file(file_id, name)
        if data:
            with open(filename, "wb") as f:
                f.write(data)
            print(f"   💾 Salvato in {filename}")
    
    print("\n" + "=" * 60)
    print("✅ COMPLETATO")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrotto dall'utente")
    except Exception as e:
        print(f"\n❌ Errore: {e}")
        import traceback
        traceback.print_exc()