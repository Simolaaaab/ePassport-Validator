import hashlib
from asn1crypto import cms, x509, core
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import subprocess
import tempfile
import os

# --- DEFINIZIONI ASN.1 NECESSARIE PER IL PARSING ---
# Definiamo la struttura interna del SOD (LDS Security Object) secondo ICAO 9303
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
    """
    Implements Passive Authentication (PA) defined in ICAO Doc 9303.
    """

    def __init__(self, sod_bytes, dg1_bytes, csca_folder="certs/"):
        self.sod_bytes = sod_bytes
        self.dg1_bytes = dg1_bytes
        self.csca_folder = csca_folder
        
        # Internal state
        self.signed_data = None
        self.ds_cert = None
        self.algo_map = {'sha256': hashlib.sha256, 'sha1': hashlib.sha1, 'sha512': hashlib.sha512}

    def verify_integrity(self):
        """Step 1: Check if DG1 has been tampered with."""
        print("[*] Parsing EF.SOD (ASN.1 Structure)...")
        
        content_info = cms.ContentInfo.load(self.sod_bytes)
        if content_info['content_type'].native != 'signed_data':
            raise Exception("SOD is not a SignedData structure")
        
        self.signed_data = content_info['content']
        
        # 1. Estrazione del contenuto incapsulato (LDS Security Object)
        encap_content_info = self.signed_data['encap_content_info']
        content_bytes = encap_content_info['content'].native
        
        # 2. Parsing della struttura logica con le classi definite sopra
        lds_so = LDSSecurityObject.load(content_bytes)
        
        # 3. Trovare l'algoritmo di hash dichiarato nel SOD
        algo_oid = lds_so['hash_algorithm']['algorithm'].native
        print(f"    -> SOD Hash Algorithm: {algo_oid}")
        
        if algo_oid not in self.algo_map:
            raise Exception(f"Unsupported hash algorithm: {algo_oid}")
            
        # 4. Calcolare l'hash del TUO DG1 locale
        hasher = self.algo_map[algo_oid]()
        hasher.update(self.dg1_bytes)
        calculated_hash = hasher.digest()
        print(f"    -> Calculated DG1 Hash: {calculated_hash.hex()[:10]}...")

        # 5. CONFRONTO REALE: Cercare l'hash del DG1 (Tag 1 = DG1) nel SOD
        stored_hash = None
        for item in lds_so['data_group_hash_values']:
            if item['data_group_number'].native == 1: # 1 identifica DG1
                stored_hash = item['data_group_hash_value'].native
                break
        
        if stored_hash is None:
            raise Exception("DG1 hash not found in SOD!")
            
        if stored_hash != calculated_hash:
            raise Exception("INTEGRITY FAILED: Hash mismatch! DG1 has been altered.")
            
        print("    -> SUCCESS: DG1 Integrity Verified (Matches SOD).")
        return True

    def verify_signature_with_openssl(self):
        print("[*] Verifying SOD Signature via OpenSSL CLI (Robust)...")
    
        # 1. Salviamo il SOD grezzo su un file temporaneo
        with tempfile.NamedTemporaryFile(delete=False) as tmp_sod:
            tmp_sod.write(self.sod_bytes)
            tmp_sod_path = tmp_sod.name

        # 2. Salviamo il certificato DS (che abbiamo estratto) su file
        with tempfile.NamedTemporaryFile(delete=False) as tmp_cert:
            # Dobbiamo salvarlo in PEM
            from cryptography.hazmat.primitives import serialization
            pem_data = self.ds_cert.public_bytes(serialization.Encoding.PEM)
            tmp_cert.write(pem_data)
            tmp_cert_path = tmp_cert.name
            
        # 3. Salviamo il certificato CSCA (Trust Anchor) su file
        # (Assumiamo di aver già trovato quello giusto nel passo verify_chain)
        # Per ora usiamo un placeholder o passiamo il path trovato
        
        try:
            # COMANDO OPENSSL:
            # openssl cms -verify -in sod.bin -inform DER -noverify -certfile ds.pem
            # -noverify: Qui verifichiamo solo la firma matematica del SOD (Step 2), 
            # non la catena (che facciamo noi a parte nello Step 3).
            
            cmd = [
                "openssl", "cms", "-verify",
                "-in", tmp_sod_path,
                "-inform", "DER",
                "-noverify",            # Non validare la catena ora (lo facciamo noi)
                "-certfile", tmp_cert_path, # Usa il certificato DS estratto
                "-out", "/dev/null"     # Non ci interessa l'output dei dati, solo lo status
            ]
            
            # Esegue il comando
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("    -> SUCCESS: OpenSSL confirms signature is VALID.")
                return True
            else:
                print(f"    -> FAILURE: OpenSSL Error:\n{result.stderr}")
                raise Exception("OpenSSL verification failed")

        finally:
            # Pulizia file temporanei
            if os.path.exists(tmp_sod_path): os.remove(tmp_sod_path)
            if os.path.exists(tmp_cert_path): os.remove(tmp_cert_path)

    def verify_chain(self):
        """Step 3: Verify DS Certificate against local CSCA (Trust Anchor)."""
        print("[*] Verifying Trust Chain (DS -> CSCA)...")
        
        verified = False
        issuer_name = self.ds_cert.issuer
        print(f"    -> Looking for issuer: {issuer_name}")

        for filename in os.listdir(self.csca_folder):
            if not filename.endswith(".pem") and not filename.endswith(".crt"):
                continue
                
            path = os.path.join(self.csca_folder, filename)
            with open(path, 'rb') as f:
                try:
                    csca_cert = load_pem_x509_certificate(f.read())
                except:
                    continue 
            
            if csca_cert.subject == issuer_name:
                print(f"    -> Found potential parent: {filename}")
                
                # --- FIX: Definizione della chiave pubblica ---
                csca_pub_key = csca_cert.public_key()
                
                try:
                    # TENTATIVO 1: Padding PSS
                    csca_pub_key.verify(
                        self.ds_cert.signature,
                        self.ds_cert.tbs_certificate_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(self.ds_cert.signature_hash_algorithm),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        self.ds_cert.signature_hash_algorithm
                    )
                    print("    -> SUCCESS: Chain Validated (PSS)!")
                    verified = True
                    break # Trovato, usciamo dal loop
                except:
                    try:
                        # TENTATIVO 2: Padding PKCS1 v1.5
                        csca_pub_key.verify(
                            self.ds_cert.signature,
                            self.ds_cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            self.ds_cert.signature_hash_algorithm
                        )
                        print("    -> SUCCESS: Chain Validated (PKCS1 v1.5)!")
                        verified = True
                        break
                    except Exception as e:
                        pass # Prova prossima chiave
        
        if not verified:
            raise Exception("Chain Verification Failed: No matching CSCA found or Invalid Signature.")
            
        return True