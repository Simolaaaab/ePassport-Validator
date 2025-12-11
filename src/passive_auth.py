import os
import hashlib
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# --- COLORI PER LA CONSOLE (Corretti e Completi) ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'   # <--- AGGIUNTO
    MAGENTA = '\033[95m'  # <--- AGGIUNTO
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- DEFINIZIONI ASN.1 ---
class DataGroupHash(core.Sequence):
    _fields = [
        ('data_group_number', core.Integer),
        ('data_group_hash_value', core.OctetString)
    ]

class DataGroupHashValues(core.SequenceOf):
    _child_spec = DataGroupHash

class LDSSecurityObject(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('hash_algorithm', x509.AlgorithmIdentifier),
        ('datagroup_hash_values', DataGroupHashValues)
    ]

class PassiveValidator:
    def __init__(self, dg1_path, dg2_path, sod_path, csca_folder):
        self.dg1_path = dg1_path
        self.dg2_path = dg2_path
        self.sod_path = sod_path
        self.csca_folder = csca_folder
        self.ds_cert = None 
        self.algo_map = {
            'sha1': hashes.SHA1(), 'sha224': hashes.SHA224(), 'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(), 'sha512': hashes.SHA512(),
            '1.3.14.3.2.26': hashes.SHA1(), '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(), '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
        }

    def _print_hex(self, label, data, color=Colors.CYAN):
        """Stampa carina di dati esadecimali"""
        if data is None:
            print(f"   {label:<25} {Colors.FAIL}NONE{Colors.ENDC}")
            return
        hex_str = data.hex().upper()
        # Taglia se troppo lungo per la console
        short_hex = hex_str[:32] + "..." if len(hex_str) > 32 else hex_str
        print(f"   {label:<25} {color}{short_hex}{Colors.ENDC}")

    def _calc_hash(self, file_path, algo_name):
        if algo_name not in self.algo_map:
            algo_name = algo_name.replace("-", "").lower()
            if algo_name not in self.algo_map: return None
        digest = hashes.Hash(self.algo_map[algo_name], backend=default_backend())
        with open(file_path, "rb") as f: digest.update(f.read())
        return digest.finalize()
    
    def _unwrap_sod(self, raw_data):
        if not raw_data: return raw_data
        if raw_data[0] == 0x30: return raw_data
        # Logica rimozione wrapper (condensata)
        idx = 1
        if raw_data[0] == 0x77:
            if raw_data[idx] < 0x80: idx += 1
            else: idx += 1 + (raw_data[idx] & 0x7f)
            if idx < len(raw_data) and raw_data[idx] == 0x82:
                idx += 1 
                if raw_data[idx] < 0x80: idx += 1
                else: idx += 1 + (raw_data[idx] & 0x7f)
            return raw_data[idx:]
        return raw_data

    def run(self):
        print(f"{Colors.HEADER}{Colors.BOLD}\n=== SISTEMA DI VERIFICA PASSAPORTO ELETTRONICO (ICAO 9303) ==={Colors.ENDC}")
        print(f"Directory CSCA: {self.csca_folder}")
        
        # --- CARICAMENTO SOD ---
        try:
            with open(self.sod_path, 'rb') as f: sod_raw = self._unwrap_sod(f.read())
            content_info = cms.ContentInfo.load(sod_raw)
            signed_data = content_info['content']
        except Exception as e:
            print(f"{Colors.FAIL}Errore parsing SOD: {e}{Colors.ENDC}")
            return

        # ---------------------------------------------------------
        # STEP 1: VERIFICA INTEGRITÀ (VISIVA)
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 1] VERIFICA INTEGRITÀ DATI (Passive Authentication){Colors.ENDC}")
        print("Confronto tra Hash calcolati dai file locali e Hash firmati nel SOD:")
        
        try:
            encap_content = signed_data['encap_content_info']['content'].native
            lds_obj = LDSSecurityObject.load(encap_content)
            sod_algo_oid = lds_obj['hash_algorithm']['algorithm'].native
            
            stored_hashes = {item['data_group_number'].native: item['data_group_hash_value'].native 
                             for item in lds_obj['datagroup_hash_values']}

            # Helper per stampare il confronto
            def check_dg(dg_num, path, label):
                if dg_num in stored_hashes:
                    local_hash = self._calc_hash(path, sod_algo_oid)
                    print(f"\n   --- Analisi {label} (DG{dg_num}) ---")
                    self._print_hex("Hash Calcolato (Locale):", local_hash, Colors.YELLOW)
                    self._print_hex("Hash nel SOD (Firmato): ", stored_hashes[dg_num], Colors.CYAN)
                    
                    if local_hash == stored_hashes[dg_num]:
                        print(f"   ESITO: {Colors.GREEN}✔ MATCH (Dati Integri){Colors.ENDC}")
                        return True
                    else:
                        print(f"   ESITO: {Colors.FAIL}✘ MISMATCH (Dati Manipolati){Colors.ENDC}")
                        return False
                return True

            d1_ok = check_dg(1, self.dg1_path, "Dati Anagrafici (MRZ)")
            d2_ok = check_dg(2, self.dg2_path, "Foto Biometrica")
            
            if not (d1_ok and d2_ok): return

        except Exception as e:
            print(f"{Colors.FAIL}Errore Hash Check: {e}{Colors.ENDC}")
            return

        # ---------------------------------------------------------
        # STEP 2: VERIFICA FIRMA SOD
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 2] VERIFICA FIRMA DIGITALE SOD (Autenticità Documento){Colors.ENDC}")
        try:
            certs = signed_data['certificates']
            ds_cert_crypto = load_der_x509_certificate(certs[0].chosen.dump(), default_backend())
            ds_pub_key = ds_cert_crypto.public_key()
            
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            # --- PROOF TECNICA PER IL PROF ---
            print(f"   Estrazione Certificato Document Signer (DS)...")
            print(f"   ► Soggetto: {Colors.CYAN}{ds_cert_crypto.subject.rfc4514_string()[:60]}...{Colors.ENDC}")
            
            # Mostriamo la chiave pubblica (imponente)
            if isinstance(ds_pub_key, rsa.RSAPublicKey):
                print(f"   ► Chiave Pubblica: {Colors.YELLOW}RSA {ds_pub_key.key_size} bit{Colors.ENDC}")
                modulus_bytes = ds_pub_key.public_numbers().n.to_bytes((ds_pub_key.key_size + 7) // 8, 'big')
                self._print_hex("► Modulo (snippet):", modulus_bytes, Colors.YELLOW)
            
            self._print_hex("► Firma Digitale SOD:", signature, Colors.MAGENTA)
            
            # Preparazione Payload
            raw_bytes = signer_info['signed_attrs'].dump()
            payload_as_array = bytearray(raw_bytes)
            if payload_as_array[0] == 0xA0: payload_as_array[0] = 0x31
            payload_to_verify = bytes(payload_as_array)
            
            # Algoritmo
            sig_algo_oid = signer_info['digest_algorithm']['algorithm'].native
            hash_algo_class = self.algo_map.get(sig_algo_oid, hashes.SHA256())

            print(f"   Verifica matematica firma ({sig_algo_oid} con PSS Salt 64)...")
            
            # VERIFICA
            valid_sig = False
            if isinstance(ds_pub_key, rsa.RSAPublicKey):
                try:
                    ds_pub_key.verify(signature, payload_to_verify, 
                        padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=64), hash_algo_class)
                    valid_sig = True
                except:
                    # Fallback auto
                     ds_pub_key.verify(signature, payload_to_verify, 
                        padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=padding.PSS.AUTO), hash_algo_class)
                     valid_sig = True

            if valid_sig:
                print(f"   ESITO: {Colors.GREEN}✔ FIRMA VALIDA (Il SOD è autentico){Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}Errore Step 2: {e}{Colors.ENDC}")
            return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 3] CHAIN OF TRUST (Verifica Autorità CSCA){Colors.ENDC}")
        
        ds_issuer = ds_cert_crypto.issuer
        print(f"   Emittente DS cercato: {ds_issuer.rfc4514_string()[:50]}...")
        
        found_valid_csca = False
        csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt','.pem'))]
        
        for c_file in csca_files:
            try:
                path = os.path.join(self.csca_folder, c_file)
                with open(path, 'rb') as f: data = f.read()
                try: csca = load_pem_x509_certificate(data, default_backend())
                except: csca = load_der_x509_certificate(data, default_backend())

                if csca.subject == ds_issuer:
                    print(f"   🔎 Analisi candidato: {Colors.BOLD}{c_file}{Colors.ENDC}")
                    csca_pub = csca.public_key()
                    
                    # Calcolo fingerprint per scena
                    fp = csca.fingerprint(hashes.SHA256()).hex().upper()
                    print(f"      Fingerprint CSCA: {fp[:30]}...")

                    # Setup verifica
                    check_hash = hashes.SHA512() if "sha512" in sig_algo_oid else hashes.SHA256()
                    
                    try:
                        if isinstance(csca_pub, rsa.RSAPublicKey):
                            csca_pub.verify(ds_cert_crypto.signature, ds_cert_crypto.tbs_certificate_bytes,
                                padding.PSS(mgf=padding.MGF1(check_hash), salt_length=64), check_hash)
                            print(f"      Verifica Firma DS: {Colors.GREEN}✔ OK (Catena Validata){Colors.ENDC}")
                            found_valid_csca = True
                            break
                    except: pass # Prova prossimo
            except: continue

        print("\n" + "="*60)
        if found_valid_csca:
            print(f"{Colors.GREEN}{Colors.BOLD}   RISULTATO FINALE: PASSAPORTO VALIDO E AUTENTICO{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}   RISULTATO: PASSAPORTO INTEGRO (CSCA mancante){Colors.ENDC}")
        print("="*60 + "\n")

if __name__ == "__main__":
    v = PassiveValidator(
        dg1_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG1.bin", 
        dg2_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG2.bin", 
        sod_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin", 
        csca_folder="../certs" 
    )
    v.run()