import os
import sys
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.x509 import load_pem_x509_crl, load_der_x509_crl

# --- COLORI ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

# --- ASN.1 ---
class DataGroupHash(core.Sequence):
    _fields = [('dg_num', core.Integer), ('dg_hash', core.OctetString)]
class DataGroupHashValues(core.SequenceOf):
    _child_spec = DataGroupHash
class LDSSecurityObject(core.Sequence):
    _fields = [('version', core.Integer), ('hash_algo', x509.AlgorithmIdentifier), ('dg_hashes', DataGroupHashValues)]

class PassiveValidator:
    def __init__(self, dg1_path, dg2_path, sod_path, csca_folder, crl_path):
        self.paths = {'DG1': dg1_path, 'DG2': dg2_path, 'SOD': sod_path}
        self.csca_folder = csca_folder
        self.crl_path = crl_path
        
        self.algo_map = {
            'sha1': hashes.SHA1(), 'sha224': hashes.SHA224(), 'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(), 'sha512': hashes.SHA512(),
            '1.3.14.3.2.26': hashes.SHA1(), '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(), '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
        }

    def _log(self, key, value, color=Colors.CYAN, indent=3):
        print(f"{' ' * indent}{key:<30}: {color}{value}{Colors.ENDC}")

    def _print_hex(self, label, data, indent=3):
        if not data: return
        h = data.hex().upper()
        preview = h[:40] + "..." if len(h) > 40 else h
        self._log(label, preview, Colors.YELLOW, indent)

    def _calc_hash(self, file_path, algo_name):
        algo = self.algo_map.get(algo_name.replace("-", "").lower())
        if not algo: return None
        h = hashes.Hash(algo, backend=default_backend())
        with open(file_path, "rb") as f: h.update(f.read())
        return h.finalize()

    def _unwrap_sod(self, raw):
        if not raw or raw[0] == 0x30: return raw
        try:
            idx = 1
            if raw[0] == 0x77:
                idx += 1 if raw[idx] < 0x80 else 1 + (raw[idx] & 0x7f)
                if idx < len(raw) and raw[idx] == 0x82:
                    idx += 1
                    idx += 1 if raw[idx] < 0x80 else 1 + (raw[idx] & 0x7f)
                return raw[idx:]
        except: pass
        return raw

    def run(self):
        print(f"\n{Colors.HEADER}{Colors.BOLD}=== ANALISI FORENSE PASSAPORTO ELETTRONICO (PA) ==={Colors.ENDC}")
        
        # --- CARICAMENTO SOD ---
        try:
            with open(self.paths['SOD'], 'rb') as f: 
                sod_raw = self._unwrap_sod(f.read())
            content_info = cms.ContentInfo.load(sod_raw)
            signed_data = content_info['content']
        except Exception as e:
            print(f"{Colors.FAIL}CRITICAL: Impossibile leggere il SOD: {e}{Colors.ENDC}"); return

        # ---------------------------------------------------------
        # STEP 1: INTEGRITÀ (Hashing)
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 1] VERIFICA INTEGRITÀ DATI (LDS Analysis){Colors.ENDC}")
        
        encap = signed_data['encap_content_info']['content'].native
        lds = LDSSecurityObject.load(encap)
        
        algo_oid = lds['hash_algo']['algorithm'].native
        algo_name = "SHA-512" if "2.16.840.1.101.3.4.2.3" in algo_oid else str(algo_oid)
        
        self._log("Algoritmo Hash Rilevato", f"{algo_name} (OID: {algo_oid})")
        
        stored_hashes = {i['dg_num'].native: i['dg_hash'].native for i in lds['dg_hashes']}
        all_integrity_ok = True

        for dg_name, dg_num in [('DG1 (MRZ)', 1), ('DG2 (Face)', 2)]:
            print(f"\n   Analisi {dg_name}:")
            if dg_num in stored_hashes:
                file_hash = self._calc_hash(self.paths[f'DG{dg_num}'], algo_oid)
                stored_h = stored_hashes[dg_num]
                
                self._print_hex("► Hash nel SOD", stored_h, 6)
                self._print_hex("► Hash Calcolato", file_hash, 6)
                
                if file_hash == stored_h:
                    print(f"      {Colors.GREEN}✔ INTEGRITÀ CONFERMATA{Colors.ENDC}")
                else:
                    print(f"      {Colors.FAIL}✘ MISMATCH DEI DATI{Colors.ENDC}")
                    all_integrity_ok = False
            else:
                print(f"      {Colors.GRAY}Hash non presente nel SOD{Colors.ENDC}")

        if not all_integrity_ok: return

        # ---------------------------------------------------------
        # STEP 2: FIRMA DIGITALE (Document Signer)
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 2] VERIFICA FIRMA DIGITALE SOD (Auth Check){Colors.ENDC}")
        
        certs = signed_data['certificates']
        ds_cert = load_der_x509_certificate(certs[0].chosen.dump(), default_backend())
        ds_pub = ds_cert.public_key()
        
        self._log("Certificato Firmatario (DS)", ds_cert.subject.rfc4514_string())
        self._log("Serial Number (Dec)", str(ds_cert.serial_number))
        self._log("Emittente (Issuer)", ds_cert.issuer.rfc4514_string())
        # FIX: Uso .not_valid_before che è compatibile con tutte le versioni
        self._log("Valido Dal", ds_cert.not_valid_before.strftime('%Y-%m-%d')) 
        
        if isinstance(ds_pub, rsa.RSAPublicKey):
            self._log("Tipo Chiave Pubblica", f"RSA {ds_pub.key_size} bit")
            mod_bytes = ds_pub.public_numbers().n.to_bytes((ds_pub.key_size+7)//8, 'big')
            self._print_hex("Modulo (Snippet)", mod_bytes)
        
        signer_info = signed_data['signer_infos'][0]
        sig_algo_oid = signer_info['digest_algorithm']['algorithm'].native
        signature = signer_info['signature'].native
        
        self._log("Algoritmo Firma", f"RSA-PSS con {sig_algo_oid}")
        self._print_hex("Firma Cifrata", signature)

        # Payload Patching
        raw_attrs = signer_info['signed_attrs'].dump()
        payload = bytearray(raw_attrs)
        if payload[0] == 0xA0: 
            payload[0] = 0x31 
            print(f"   {Colors.GRAY}[DEBUG] Payload patchato: Tag 0xA0 -> 0x31{Colors.ENDC}")
        
        hash_cls = self.algo_map.get(sig_algo_oid, hashes.SHA256())
        signature_ok = False
        
        if isinstance(ds_pub, rsa.RSAPublicKey):
            try:
                ds_pub.verify(signature, bytes(payload), padding.PSS(mgf=padding.MGF1(hash_cls), salt_length=64), hash_cls)
                signature_ok = True
                self._log("Metodo Verifica", "RSA-PSS (Salt=64)", Colors.GREEN)
            except:
                try:
                    ds_pub.verify(signature, bytes(payload), padding.PSS(mgf=padding.MGF1(hash_cls), salt_length=padding.PSS.AUTO), hash_cls)
                    signature_ok = True
                    self._log("Metodo Verifica", "RSA-PSS (Salt=Auto)", Colors.GREEN)
                except: pass

        if signature_ok:
            print(f"   {Colors.GREEN}✔ FIRMA DIGITALE VALIDA{Colors.ENDC}")
        else:
            print(f"   {Colors.FAIL}✘ FIRMA NON VALIDA{Colors.ENDC}"); return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 3] CHAIN OF TRUST (CSCA Validation){Colors.ENDC}")
        
        ds_issuer = ds_cert.issuer
        print(f"   Cerco genitore per: {Colors.CYAN}{ds_issuer.rfc4514_string()[:60]}...{Colors.ENDC}")
        
        chain_verified = False
        if os.path.exists(self.csca_folder):
            csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt'))]
            for f_name in csca_files:
                try:
                    with open(os.path.join(self.csca_folder, f_name), 'rb') as f: cert_data = f.read()
                    try: csca = load_pem_x509_certificate(cert_data, default_backend())
                    except: csca = load_der_x509_certificate(cert_data, default_backend())

                    if csca.subject == ds_issuer:
                        print(f"\n   🔎 Analisi Candidato: {Colors.BOLD}{f_name}{Colors.ENDC}")
                        csca_pub = csca.public_key()
                        check_hash = hashes.SHA512() if "sha512" in sig_algo_oid else hashes.SHA256()
                        
                        try:
                            if isinstance(csca_pub, rsa.RSAPublicKey):
                                csca_pub.verify(ds_cert.signature, ds_cert.tbs_certificate_bytes, 
                                                padding.PSS(mgf=padding.MGF1(check_hash), salt_length=64), check_hash)
                                chain_verified = True
                                print(f"      {Colors.GREEN}✔ FIRMA GENITORE VALIDA{Colors.ENDC}")
                                break
                        except: pass
                except: continue

        if not chain_verified:
            print(f"\n   {Colors.WARNING}⚠️  Nessun CSCA valido trovato.{Colors.ENDC}")

        # ---------------------------------------------------------
        # STEP 4: CRL (Revoca)
        # ---------------------------------------------------------
        print(f"\n{Colors.BLUE}{Colors.BOLD}[STEP 4] CONTROLLO REVOCA (CRL){Colors.ENDC}")
        crl_ok = False
        if os.path.exists(self.crl_path):
            try:
                with open(self.crl_path, "rb") as f: crl_data = f.read()
                try: crl = load_pem_x509_crl(crl_data, default_backend())
                except: crl = load_der_x509_crl(crl_data, default_backend())
                
                # FIX: Uso .last_update che è compatibile
                self._log("CRL Aggiornata", crl.last_update.strftime('%Y-%m-%d'))
                
                revoked = crl.get_revoked_certificate_by_serial_number(ds_cert.serial_number)
                if revoked:
                    print(f"      {Colors.FAIL}⛔ CERTIFICATO REVOCATO!{Colors.ENDC}")
                else:
                    print(f"      {Colors.GREEN}✔ SERIAL NUMBER NON PRESENTE IN CRL (Valido){Colors.ENDC}")
                    crl_ok = True
            except:
                print(f"   {Colors.GRAY}Impossibile leggere CRL{Colors.ENDC}")
        else:
            print(f"   {Colors.GRAY}File CRL non trovato{Colors.ENDC}")

        # VERDETTO
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        if all_integrity_ok and signature_ok and chain_verified and crl_ok:
            print(f"{Colors.GREEN}{Colors.BOLD}   VERDETTO FINALE: PASSAPORTO VALIDO E AUTENTICO{Colors.ENDC}")
        else:
             print(f"{Colors.YELLOW}{Colors.BOLD}   VERDETTO FINALE: VERIFICA INCOMPLETA O FALLITA{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dumps_dir = os.path.join(base_dir, "..", "dumps")
    certs_dir = os.path.join(base_dir, "..", "certs")
    
    # ID Passaporto
    MRZ_ID = "YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02"

    v = PassiveValidator(
        dg1_path=os.path.join(dumps_dir, f"{MRZ_ID}-DG1.bin"), 
        dg2_path=os.path.join(dumps_dir, f"{MRZ_ID}-DG2.bin"), 
        sod_path=os.path.join(dumps_dir, f"{MRZ_ID}-SOD.bin"), 
        csca_folder=certs_dir,
        crl_path=os.path.join(certs_dir, "CRL_CSCA.crl")
    )
    v.run()