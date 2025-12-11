import os
import hashlib
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# --- DEFINIZIONI ASN.1 (Per leggere la struttura interna) ---
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
        # Mappa OID -> Oggetti Hash Cryptography
        self.algo_map = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512(),
            '1.3.14.3.2.26': hashes.SHA1(),
            '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
            '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
        }

    def _calc_hash(self, file_path, algo_name):
        if algo_name not in self.algo_map:
            algo_name = algo_name.replace("-", "").lower()
            if algo_name not in self.algo_map:
                # Fallback per nomi OID non mappati
                return None
        digest = hashes.Hash(self.algo_map[algo_name], backend=default_backend())
        with open(file_path, "rb") as f:
            digest.update(f.read())
        return digest.finalize()
    
    def _unwrap_sod(self, raw_data):
        """Rimuove i wrapper ICAO (Tag 77/82) per arrivare al contenuto 30 (Sequence)"""
        if not raw_data: return raw_data
        if raw_data[0] == 0x30: return raw_data
        
        if raw_data[0] == 0x77:
            print("   ⚠️  Rilevato Wrapper 0x77. Rimozione in corso...")
            idx = 1
            if raw_data[idx] < 0x80: idx += 1
            else: idx += 1 + (raw_data[idx] & 0x7f)
            
            if idx < len(raw_data) and raw_data[idx] == 0x82:
                print("   ⚠️  Rilevato Tag 0x82. Rimozione in corso...")
                idx += 1 
                if raw_data[idx] < 0x80: idx += 1
                else: idx += 1 + (raw_data[idx] & 0x7f)
            return raw_data[idx:]
        return raw_data

    def run(self):
        print("\n=== AVVIO PASSIVE AUTHENTICATION ===")
        print(f"Cartella CSCA: {self.csca_folder}")
        
        # --- CARICAMENTO SOD ---
        try:
            with open(self.sod_path, 'rb') as f: sod_raw_dirty = f.read()
            sod_raw = self._unwrap_sod(sod_raw_dirty)
            content_info = cms.ContentInfo.load(sod_raw)
            if content_info['content_type'].native != 'signed_data':
                print("❌ Errore: Il SOD non è un SignedData.")
                return
            signed_data = content_info['content']
        except Exception as e:
            print(f"❌ Errore parsing SOD: {e}")
            return

        # ---------------------------------------------------------
        # STEP 1: VERIFICA INTEGRITÀ
        # ---------------------------------------------------------
        print("\n--- 1. VERIFICA INTEGRITÀ DATI ---")
        try:
            encap_content = signed_data['encap_content_info']['content'].native
            lds_obj = LDSSecurityObject.load(encap_content)
            sod_algo_oid = lds_obj['hash_algorithm']['algorithm'].native
            print(f"[*] Algoritmo Hash Passaporto (OID): {sod_algo_oid}")
            
            stored_hashes = {item['data_group_number'].native: item['data_group_hash_value'].native 
                             for item in lds_obj['datagroup_hash_values']}

            # Verifica DG1
            if 1 in stored_hashes:
                calc_dg1 = self._calc_hash(self.dg1_path, sod_algo_oid)
                if calc_dg1 == stored_hashes[1]:
                    print("✅ DG1 INTEGRITY: OK")
                else:
                    print(f"❌ DG1 INTEGRITY: FALLITA!")
                    return 
            
            # Verifica DG2
            if 2 in stored_hashes:
                calc_dg2 = self._calc_hash(self.dg2_path, sod_algo_oid)
                if calc_dg2 == stored_hashes[2]:
                    print("✅ DG2 INTEGRITY: OK")
                else:
                    print("❌ DG2 INTEGRITY: FALLITA!")
                    return
        except Exception as e:
            print(f"❌ Errore Hash Check: {e}")
            return

        # ---------------------------------------------------------
        # STEP 2: VERIFICA FIRMA SOD
        # ---------------------------------------------------------
        print("\n--- 2. VERIFICA FIRMA DIGITALE SOD ---")
        try:
            certs = signed_data['certificates']
            ds_cert_x509 = certs[0].chosen
            self.ds_cert = ds_cert_x509.dump()
            ds_cert_crypto = load_der_x509_certificate(self.ds_cert, default_backend())
            ds_pub_key = ds_cert_crypto.public_key()
            
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            # BYTE PATCHING (A0 -> 31)
            raw_bytes = signer_info['signed_attrs'].dump()
            payload_as_array = bytearray(raw_bytes)
            if payload_as_array[0] == 0xA0:
                payload_as_array[0] = 0x31
            payload_to_verify = bytes(payload_as_array)

            # Algoritmo Firma
            sig_algo_oid = signer_info['digest_algorithm']['algorithm'].native
            hash_algo_class = self.algo_map.get(sig_algo_oid, hashes.SHA256())
            
            # PROOF VISIVA
            print(f"   ► Algoritmo Firma Rilevato: {sig_algo_oid}")
            print(f"   ► Serial Number DS: {ds_cert_crypto.serial_number}")

            # Verifica SOD
            if isinstance(ds_pub_key, rsa.RSAPublicKey):
                try:
                    # PROVA 1: PSS con Salt 64 (Specifico Italia SHA512)
                    ds_pub_key.verify(
                        signature, payload_to_verify, 
                        padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=64),
                        hash_algo_class
                    )
                    print("✅ Firma SOD (RSA PSS - Salt 64): VALIDA")
                except:
                    try:
                        # PROVA 2: PSS Auto
                        ds_pub_key.verify(
                            signature, payload_to_verify, 
                            padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=padding.PSS.AUTO),
                            hash_algo_class
                        )
                        print("✅ Firma SOD (RSA PSS - Auto): VALIDA")
                    except Exception as e:
                        print(f"❌ Firma SOD Fallita: {e}")
                        return
            elif isinstance(ds_pub_key, ec.EllipticCurvePublicKey):
                 ds_pub_key.verify(signature, payload_to_verify, ec.ECDSA(hash_algo_class))
                 print("✅ Firma SOD (ECDSA): VALIDA")

        except Exception as e:
            print(f"❌ Errore Step 2: {e}")
            return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST (CSCA)
        # ---------------------------------------------------------
        print("\n--- 3. CHAIN OF TRUST (CSCA -> Document Signer) ---")
        if not os.path.exists(self.csca_folder):
            print("⚠️ Cartella CSCA non trovata.")
            return

        ds_issuer = ds_cert_crypto.issuer
        print(f"[*] DS Emesso da: {ds_issuer}")
        
        found_valid_csca = False
        
        # Filtra file cer/crt/pem
        csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt','.pem'))]
        
        for c_file in csca_files:
            try:
                path = os.path.join(self.csca_folder, c_file)
                with open(path, 'rb') as f: cert_data = f.read()
                
                # Load flessibile
                try: csca = load_pem_x509_certificate(cert_data, default_backend())
                except: csca = load_der_x509_certificate(cert_data, default_backend())

                if csca.subject == ds_issuer:
                    print(f"   🔎 Candidato trovato: {c_file}")
                    csca_pub = csca.public_key()
                    
                    # Logica specifica per RSA-PSS (ITALIA)
                    # Usiamo l'hash algorithm con cui il DS è stato firmato
                    # Di solito lo prendiamo dal certificato DS stesso
                    ds_sig_alg_oid = ds_cert_crypto.signature_algorithm_oid.dotted_string
                    
                    # Mappiamo l'OID della firma all'hash function
                    # 1.2.840.113549.1.1.13 = sha512WithRSAEncryption
                    # 1.2.840.113549.1.1.10 = rsassaPss (richiede parsing parametri, assumiamo sha512 per IT)
                    
                    check_hash = hashes.SHA512() # Default forte per IT
                    if "sha256" in ds_cert_crypto.signature_hash_algorithm.name: check_hash = hashes.SHA256()

                    try:
                        if isinstance(csca_pub, rsa.RSAPublicKey):
                            # TENTATIVO MIRATO: SALT 64 (per SHA512)
                            csca_pub.verify(
                                ds_cert_crypto.signature,
                                ds_cert_crypto.tbs_certificate_bytes,
                                padding.PSS(mgf=padding.MGF1(check_hash), salt_length=64),
                                check_hash
                            )
                            print(f"   ✅ BINGO! Chain Validated (PSS Salt 64) con {c_file}")
                            found_valid_csca = True
                            break # Trovato, usciamo
                    except:
                        # Fallback PSS Auto
                        try:
                            csca_pub.verify(
                                ds_cert_crypto.signature,
                                ds_cert_crypto.tbs_certificate_bytes,
                                padding.PSS(mgf=padding.MGF1(check_hash), salt_length=padding.PSS.AUTO),
                                check_hash
                            )
                            print(f"   ✅ BINGO! Chain Validated (PSS Auto) con {c_file}")
                            found_valid_csca = True
                            break
                        except Exception as e:
                            print(f"   ❌ Fallito su {c_file}: {e}")
            except Exception as ex:
                continue

        if found_valid_csca:
            print("\n🎉 CONGRATULAZIONI: PASSAPORTO VALIDO, AUTENTICO E FIDATO.")
        else:
            print("\n⚠️ Chain of Trust incompleta. (Verificato SOD, ma mancante CSCA padre corretto)")

if __name__ == "__main__":
    v = PassiveValidator(
        dg1_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG1.bin", 
        dg2_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG2.bin", 
        sod_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin", 
        csca_folder="../certs" 
    )
    v.run()