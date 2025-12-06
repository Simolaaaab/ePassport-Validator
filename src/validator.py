import hashlib
import subprocess
import tempfile
import os
from asn1crypto import cms, x509, core
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate, load_der_x509_crl
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# --- DEFINIZIONI ASN.1 (Invariate) ---
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
        ('data_group_hash_values', DataGroupHashValues)
    ]

class PassiveAuthValidator:
    def __init__(self, sod_bytes, dg1_bytes, csca_folder="certs/", crl_path=None):
        self.sod_bytes = sod_bytes
        self.dg1_bytes = dg1_bytes
        self.csca_folder = csca_folder
        self.crl_path = crl_path
        
        # Stato interno
        self.signed_data = None
        self.ds_cert = None # Cryptography object
        self.ds_cert_bytes = None # Raw bytes per OpenSSL
        self.algo_map = {'sha256': hashlib.sha256, 'sha1': hashlib.sha1, 'sha512': hashlib.sha512}

    def _extract_ds_certificate(self):
        """Estrae il certificato DS embedded nel SOD."""
        print("    -> Extracting Document Signer (DS) Certificate from SOD...")
        try:
            # Il campo 'certificates' è un set di certificati. Di solito ce n'è uno solo (il DS).
            # Se ce ne sono più di uno, bisognerebbe cercare quello che corrisponde al SignerIdentifier.
            certs = self.signed_data['certificates']
            
            # Prendiamo il primo certificato trovato (approccio semplificato ma efficace per passaporti)
            # Nota: certs è un SetOf, dobbiamo iterare o prendere l'indice
            for cert_choice in certs:
                # cert_choice è un oggetto 'CertificateChoices', dobbiamo prendere 'certificate'
                cert_structure = cert_choice.chosen
                self.ds_cert_bytes = cert_structure.dump()
                
                # Carichiamo in oggetto cryptography per usarlo dopo
                self.ds_cert = load_der_x509_certificate(self.ds_cert_bytes)
                print(f"       Found DS Certificate: {self.ds_cert.subject}")
                return # Trovato, usciamo
                
            raise Exception("No certificates found inside SOD")
        except Exception as e:
            raise Exception(f"Failed to extract DS cert: {e}")

    def verify_integrity(self):
        """Step 1: Check Hash SOD vs DG1 + Extract DS Cert"""
        print("\n[*] STEP 1: Parsing EF.SOD and Checking Integrity...")
        
        content_info = cms.ContentInfo.load(self.sod_bytes)
        if content_info['content_type'].native != 'signed_data':
            raise Exception("SOD is not a SignedData structure")
        
        self.signed_data = content_info['content']
        
        # A QUESTO PUNTO ESTRAIAMO IL CERTIFICATO DS (Fondamentale per i prossimi step)
        self._extract_ds_certificate()

        # 1. Parsing LDS Object
        encap_content_info = self.signed_data['encap_content_info']
        content_bytes = encap_content_info['content'].native
        lds_so = LDSSecurityObject.load(content_bytes)
        
        # 2. Hash Algo
        algo_oid = lds_so['hash_algorithm']['algorithm'].native
        print(f"    -> Algorithm: {algo_oid}")
        
        if algo_oid not in self.algo_map:
            raise Exception(f"Unsupported hash algorithm: {algo_oid}")
            
        # 3. Calcolo Hash DG1 Locale
        hasher = self.algo_map[algo_oid]()
        hasher.update(self.dg1_bytes)
        calculated_hash = hasher.digest()
        
        # 4. Confronto
        stored_hash = None
        for item in lds_so['data_group_hash_values']:
            if item['data_group_number'].native == 1:
                stored_hash = item['data_group_hash_value'].native
                break
        
        if stored_hash != calculated_hash:
            print(f"       Stored: {stored_hash.hex()[:10]}...")
            print(f"       Calcd : {calculated_hash.hex()[:10]}...")
            raise Exception("INTEGRITY FAILED: DG1 Hash mismatch!")
            
        print("    -> SUCCESS: DG1 Integrity Verified.")
        return True

    def verify_signature_with_openssl(self):
        """Step 2: Verify SOD Signature using extracted Cert"""
        print("\n[*] STEP 2: Verifying SOD Signature (via OpenSSL)...")
        
        if not self.ds_cert_bytes:
            raise Exception("DS Certificate not extracted yet!")

        # Creiamo i file temporanei necessari
        with tempfile.NamedTemporaryFile(delete=False) as tmp_sod:
            tmp_sod.write(self.sod_bytes)
            tmp_sod_path = tmp_sod.name
            
        with tempfile.NamedTemporaryFile(delete=False) as tmp_cert:
            # OpenSSL vuole il cert in PEM solitamente per l'argomento -certfile, ma accetta anche DER
            # Usiamo PEM per compatibilità massima
            from cryptography.hazmat.primitives import serialization
            pem_data = self.ds_cert.public_bytes(serialization.Encoding.PEM)
            tmp_cert.write(pem_data)
            tmp_cert_path = tmp_cert.name
            
        try:
            # Il trucco qui è estrarre il contenuto firmato e verificarlo matematicamente
            # contro il certificato che abbiamo estratto noi stessi dal SOD.
            cmd = [
                "openssl", "cms", "-verify",
                "-in", tmp_sod_path,
                "-inform", "DER",
                "-noverify",            # Non verificare la catena (lo facciamo nel step 3)
                "-certfile", tmp_cert_path,
                "-out", "/dev/null"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("    -> SUCCESS: SOD Signature is mathematicaly VALID.")
                return True
            else:
                # Spesso OpenSSL fallisce se non trova la root CA anche con -noverify
                # ma se l'errore è "certificate verify failed" potrebbe essere la catena.
                # Se l'errore è "digest failure", allora la firma è rotta.
                print(f"    -> FAILURE OpenSSL: {result.stderr.strip()}")
                return False # O raise Exception
        finally:
            if os.path.exists(tmp_sod_path): os.remove(tmp_sod_path)
            if os.path.exists(tmp_cert_path): os.remove(tmp_cert_path)

    def check_crl(self, serial_number, issuer):
        """Helper per controllare se un seriale è nella CRL"""
        if not self.crl_path or not os.path.exists(self.crl_path):
            print("    -> [Warning] No CRL provided or file not found. Skipping.")
            return True # Assumiamo valido se non possiamo controllare

        try:
            with open(self.crl_path, 'rb') as f:
                crl = load_der_x509_crl(f.read()) # O load_pem... dipende dal tuo file
            
            # Controllo basilare: il certificato è stato revocato?
            revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_number)
            if revoked_cert is not None:
                print(f"    -> CRITICAL: Certificate Serial {serial_number} is REVOKED!")
                return False
            return True
        except Exception as e:
            print(f"    -> [Warning] CRL Parsing error: {e}")
            return True

    def verify_chain(self):
        """Step 3: Verify DS -> CSCA (Local Trust Anchor)"""
        print("\n[*] STEP 3: Verifying Trust Chain (DS -> CSCA)...")
        
        issuer_name = self.ds_cert.issuer
        print(f"    -> DS Issuer: {issuer_name}")

        csca_found = False
        
        # 1. Cerchiamo il certificato CSCA giusto nella cartella
        for filename in os.listdir(self.csca_folder):
            path = os.path.join(self.csca_folder, filename)
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                    # Tentativo di load intelligente (PEM o DER)
                    if b"-----BEGIN CERTIFICATE-----" in data:
                        csca_cert = load_pem_x509_certificate(data)
                    else:
                        csca_cert = load_der_x509_certificate(data)
            except:
                continue 
            
            # Verifichiamo se Subject del CSCA == Issuer del DS
            # Nota: il confronto diretto degli oggetti Name a volte fallisce per encoding diversi,
            # ma cryptography lo gestisce abbastanza bene.
            if csca_cert.subject == issuer_name:
                print(f"    -> Candidate CSCA found: {filename}")
                
                # --- VERIFICA FIRMA ---
                public_key = csca_cert.public_key()
                signature = self.ds_cert.signature
                tbs_data = self.ds_cert.tbs_certificate_bytes
                hash_algo = self.ds_cert.signature_hash_algorithm
                
                # Prova PSS (Comune nei nuovi passaporti)
                try:
                    public_key.verify(
                        signature, tbs_data,
                        padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
                        hash_algo
                    )
                    print("    -> Signature OK (PSS)")
                    csca_found = True
                except:
                    # Prova PKCS1 v1.5 (Passaporti più vecchi)
                    try:
                        public_key.verify(
                            signature, tbs_data,
                            padding.PKCS1v15(),
                            hash_algo
                        )
                        print("    -> Signature OK (PKCS1 v1.5)")
                        csca_found = True
                    except Exception as e:
                        print(f"    -> Signature Verification Failed for {filename}: {e}")
                        continue
                
                if csca_found:
                    # --- VERIFICA CRL ---
                    print("    -> Checking CRL...")
                    if not self.check_crl(self.ds_cert.serial_number, issuer_name):
                        raise Exception("DS Certificate is REVOKED!")
                    print("    -> CRL Check Passed (or skipped).")
                    
                    print("    -> SUCCESS: Chain of Trust validated.")
                    return True

        raise Exception("Chain Verification Failed: No matching valid CSCA found.")

# --- ESEMPIO DI UTILIZZO ---
# Assumi di avere 'sod_bytes' e 'dg1_bytes' letti dallo script precedente
if __name__ == "__main__":
    # Esempio fittizio di caricamento
    # sod_bytes = open("sod.bin", "rb").read()
    # dg1_bytes = open("dg1.bin", "rb").read()
    
    # validator = PassiveAuthValidator(sod_bytes, dg1_bytes, csca_folder="csca_certs/", crl_path="master_list.crl")
    # validator.verify_integrity()
    # validator.verify_signature_with_openssl()
    # validator.verify_chain()
    pass