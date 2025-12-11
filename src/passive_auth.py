import os
import json
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.x509 import load_pem_x509_crl, load_der_x509_crl # <--- NUOVO IMPORT

# --- COLORI ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- ASN.1 ---
class DataGroupHash(core.Sequence):
    _fields = [('dg_num', core.Integer), ('dg_hash', core.OctetString)]
class DataGroupHashValues(core.SequenceOf):
    _child_spec = DataGroupHash
class LDSSecurityObject(core.Sequence):
    _fields = [('version', core.Integer), ('hash_algo', x509.AlgorithmIdentifier), ('dg_hashes', DataGroupHashValues)]

class PassiveValidator:
    def __init__(self, dg1_path, dg2_path, sod_path, csca_folder, crl_path): # <--- AGGIUNTO crl_path
        self.dg1_path = dg1_path
        self.dg2_path = dg2_path
        self.sod_path = sod_path
        self.csca_folder = csca_folder
        self.crl_path = crl_path # <--- SALVATO
        
        self.report = {
            "passport_structure": {"algorithm": None, "sod_present": False},
            "integrity_check": {},
            "digital_signature": {},
            "chain_of_trust": {},
            "revocation_status": "NOT CHECKED", # <--- NUOVO CAMPO
            "final_verdict": "UNKNOWN"
        }

        self.algo_map = {
            'sha1': hashes.SHA1(), 'sha224': hashes.SHA224(), 'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(), 'sha512': hashes.SHA512(),
            '1.3.14.3.2.26': hashes.SHA1(), '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(), '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
        }

    def _print_hex(self, label, data, color=Colors.CYAN):
        if data is None: return
        hex_str = data.hex().upper()
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
        
        # --- CARICAMENTO SOD ---
        try:
            with open(self.sod_path, 'rb') as f: sod_raw = self._unwrap_sod(f.read())
            content_info = cms.ContentInfo.load(sod_raw)
            signed_data = content_info['content']
            self.report["passport_structure"]["sod_present"] = True
        except Exception as e:
            print(f"{Colors.FAIL}Errore parsing SOD: {e}{Colors.ENDC}")
            return

        # ---------------------------------------------------------
        # STEP 1: INTEGRITÀ
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 1] VERIFICA INTEGRITÀ DATI{Colors.ENDC}")
        try:
            encap_content = signed_data['encap_content_info']['content'].native
            lds_obj = LDSSecurityObject.load(encap_content)
            sod_algo_oid = lds_obj['hash_algo']['algorithm'].native
            self.report["passport_structure"]["algorithm"] = sod_algo_oid
            stored_hashes = {item['dg_num'].native: item['dg_hash'].native for item in lds_obj['dg_hashes']}

            def audit_dg(num, path, name):
                if num in stored_hashes:
                    local_h = self._calc_hash(path, sod_algo_oid)
                    is_valid = (stored_hashes[num] == local_h)
                    self.report["integrity_check"][name] = {"match": is_valid}
                    if is_valid: print(f"   DG{num} ({name}): {Colors.GREEN}MATCH{Colors.ENDC}")
                    return is_valid
                return False

            if not (audit_dg(1, self.dg1_path, "DG1") and audit_dg(2, self.dg2_path, "DG2")): return
        except Exception as e:
            print(f"Errore Hash: {e}"); return

        # ---------------------------------------------------------
        # STEP 2: FIRMA DIGITALE
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 2] VERIFICA FIRMA SOD{Colors.ENDC}")
        try:
            certs = signed_data['certificates']
            ds_cert = load_der_x509_certificate(certs[0].chosen.dump(), default_backend())
            ds_pub = ds_cert.public_key()
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            raw_bytes = signer_info['signed_attrs'].dump()
            payload = bytearray(raw_bytes)
            if payload[0] == 0xA0: payload[0] = 0x31
            payload_to_verify = bytes(payload)
            
            algo_oid = signer_info['digest_algorithm']['algorithm'].native
            hash_cls = self.algo_map.get(algo_oid, hashes.SHA256())

            self.report["digital_signature"] = {
                "serial_number": ds_cert.serial_number, # Importante per la CRL
                "signature_valid": False
            }

            valid = False
            if isinstance(ds_pub, rsa.RSAPublicKey):
                try:
                    ds_pub.verify(signature, payload_to_verify, padding.PSS(mgf=padding.MGF1(hash_cls), salt_length=64), hash_cls)
                    valid = True
                except:
                     try:
                        ds_pub.verify(signature, payload_to_verify, padding.PSS(mgf=padding.MGF1(hash_cls), salt_length=padding.PSS.AUTO), hash_cls)
                        valid = True
                     except: pass
            elif isinstance(ds_pub, ec.EllipticCurvePublicKey):
                 try:
                    ds_pub.verify(signature, payload_to_verify, ec.ECDSA(hash_cls))
                    valid = True
                 except: pass

            self.report["digital_signature"]["signature_valid"] = valid
            if valid: print(f"   Firma SOD: {Colors.GREEN}VALIDA{Colors.ENDC}")

        except Exception as e:
            print(f"Errore Firma: {e}"); return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 3] CHAIN OF TRUST (CSCA){Colors.ENDC}")
        ds_issuer = ds_cert.issuer
        
        self.report["chain_of_trust"] = {"csca_found": False, "chain_valid": False}
        
        # A. Cerca Certificato CSCA
        if os.path.exists(self.csca_folder):
            for f_name in os.listdir(self.csca_folder):
                if not f_name.lower().endswith('.cer'): continue
                try:
                    with open(os.path.join(self.csca_folder, f_name), 'rb') as f: data = f.read()
                    try: csca = load_pem_x509_certificate(data, default_backend())
                    except: csca = load_der_x509_certificate(data, default_backend())
                    
                    if csca.subject == ds_issuer:
                        csca_pub = csca.public_key()
                        check_hash = hashes.SHA512() if "sha512" in algo_oid else hashes.SHA256()
                        try:
                            if isinstance(csca_pub, rsa.RSAPublicKey):
                                csca_pub.verify(ds_cert.signature, ds_cert.tbs_certificate_bytes, padding.PSS(mgf=padding.MGF1(check_hash), salt_length=64), check_hash)
                                self.report["chain_of_trust"] = {"csca_found": True, "filename": f_name, "chain_valid": True}
                                print(f"   CSCA Trovato: {Colors.GREEN}{f_name}{Colors.ENDC}")
                                break
                        except: pass
                except: continue

        # ---------------------------------------------------------
        # STEP 4: CONTROLLO CRL (REVOCATION CHECK) - NUOVO!
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 4] CONTROLLO REVOCA (CRL){Colors.ENDC}")
        
        if os.path.exists(self.crl_path):
            try:
                with open(self.crl_path, "rb") as f: crl_data = f.read()
                # Carica CRL (Tenta PEM poi DER)
                try: crl = load_pem_x509_crl(crl_data, default_backend())
                except: crl = load_der_x509_crl(crl_data, default_backend())
                
                print(f"   Analisi CRL emessa da: {crl.issuer.rfc4514_string()[:50]}...")
                
                # Check Serial Number
                ds_serial = ds_cert.serial_number
                print(f"   Cerco Serial Number DS: {Colors.YELLOW}{ds_serial}{Colors.ENDC}")
                
                revoked_entry = crl.get_revoked_certificate_by_serial_number(ds_serial)
                
                if revoked_entry is not None:
                    print(f"   STATO: {Colors.FAIL}REVOCATO!{Colors.ENDC} (Data: {revoked_entry.revocation_date})")
                    self.report["revocation_status"] = "REVOKED"
                else:
                    print(f"   STATO: {Colors.GREEN}NON REVOCATO (Valido){Colors.ENDC}")
                    self.report["revocation_status"] = "OK"
                    
            except Exception as e:
                print(f"   {Colors.WARNING}Impossibile leggere CRL: {e}{Colors.ENDC}")
                self.report["revocation_status"] = "ERROR_READING_CRL"
        else:
            print(f"   {Colors.WARNING}File CRL non trovato: {self.crl_path}{Colors.ENDC}")
            self.report["revocation_status"] = "CRL_MISSING"

        # VERDETTO FINALE (Include CRL Check)
        is_clean = (self.report["integrity_check"].get("DG1", {}).get("match") and 
                    self.report["digital_signature"].get("signature_valid") and 
                    self.report["chain_of_trust"].get("chain_valid") and
                    self.report["revocation_status"] == "OK") # <--- Importante!
        
        self.report["final_verdict"] = "AUTHENTIC" if is_clean else "FAILED"

        print("\n" + "="*60)
        print(f"{Colors.YELLOW}REPORT STRUTTURATO:{Colors.ENDC}")
        print(json.dumps(self.report, indent=4))
        print("="*60)

if __name__ == "__main__":
    # Aggiorna il percorso della CRL qui sotto!
    v = PassiveValidator(
        dg1_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG1.bin", 
        dg2_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG2.bin", 
        sod_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin", 
        csca_folder="../certs",
        crl_path="../certs/CRL_CSCA.crl" # <--- PUNTA AL TUO FILE CRL SCARICATO
    )
    v.run()