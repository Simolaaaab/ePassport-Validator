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
# 2. FUNZIONI UTILI
# ==========================================

def derive_key(seed, mode):
    """Deriva le chiavi (Kenc/Kmac) dal Seed usando SHA-1"""
    # Mode 1 = Encrypt, Mode 2 = MAC
    c = bytes([0, 0, 0, mode])
    d = hashlib.sha1(seed + c).digest()
    return d[:8] + d[8:16]

def send_apdu(connection, apdu, name=""):
    resp, sw1, sw2 = connection.transmit(apdu)
    sw = (sw1 << 8) + sw2
    return resp, sw

def pad(data):
    """Padding ISO per il MAC (80 00...)"""
    return data + b'\x80' + b'\x00' * (7 - (len(data) % 8))

# ==========================================
# 3. MAIN
# ==========================================

def main():
    print("="*60)
    print("   GENERAZIONE CHIAVI DI SESSIONE (KS)")
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
    resp_list, sw = send_apdu(connection, cmd, "Mutual Auth")

    if sw != 0x9000:
        print("❌ Auth Fallita.")
        sys.exit(1)
        
    print("✅ Auth OK! Ora calcoliamo le Session Keys...")

    # ==========================================================
    # QUSTA È LA PARTE CHE MANCAVA (FIGURA 4 IN BASSO)
    # ==========================================================
    
    # La risposta del passaporto contiene dati cifrati (E_ICC e M_ICC)
    # Dobbiamo decifrarli per trovare K_ICC (il segreto del passaporto)
    resp_data = bytes(resp_list)
    
    # La risposta è solitamente: [E_ICC (32 bytes)] [M_ICC (8 bytes)] (Status Word esclusa)
    # Nota: alcuni passaporti mandano più dati, ma K_ICC è nei dati cifrati.
    if len(resp_data) < 32:
        print("Errore: Risposta troppo corta dal passaporto.")
        sys.exit()

    e_icc = resp_data[:32] # La parte cifrata
    
    # Decifriamo la risposta usando K_enc (MRZ)
    # NOTA: L'IV per la risposta è l'ultimo blocco cifrato inviato da noi (M_IFD o E_IFD finale)
    # Ma per standard BAC response decryption, l'IV è spesso zero. Proviamo zero.
    iv_resp = bytes([0]*8) 
    decryptor = DES3.new(k_enc, DES3.MODE_CBC, iv_resp)
    decrypted_response = decryptor.decrypt(e_icc)
    
    # Struttura Decifrata: [RND.ICC] [RND.IFD] [K.ICC]
    # RND.ICC (8 byte)
    # RND.IFD (8 byte)
    # K.ICC   (16 byte) <--- QUESTO CI SERVE!
    
    found_k_icc = decrypted_response[16:32]
    
    print(f"    K_IFD (Nostro): {toHexString(list(k_ifd))}")
    print(f"    K_ICC (Trovato): {toHexString(list(found_k_icc))}")

    # --- CALCOLO K_SEED (XOR) ---
    # K_seed = K_IFD XOR K_ICC
    k_seed_session = strxor(k_ifd, found_k_icc)
    
    # --- CALCOLO KS_ENC e KS_MAC ---
    ks_enc = derive_key(k_seed_session, 1)
    ks_mac = derive_key(k_seed_session, 2)
    
    # --- CALCOLO SSC (Send Sequence Counter) ---
    # SSC = RND.ICC (low 4 bytes) || RND.IFD (low 4 bytes)
    ssc = rnd_icc[-4:] + rnd_ifd[-4:]

    print("-" * 50)
    print("🔑 CHIAVI DI SESSIONE (SESSION KEYS) COMPLETE")
    print("-" * 50)
    print(f"KS_enc: {toHexString(list(ks_enc))}")
    print(f"KS_mac: {toHexString(list(ks_mac))}")
    print(f"SSC:    {toHexString(list(ssc))}")
    print("-" * 50)
    print("Ora puoi usare queste chiavi per leggere i Data Groups (es. foto).")

if __name__ == "__main__":
    main()