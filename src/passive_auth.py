import os
import hashlib
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

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
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512(),

            # OID Numerici (quello che ti mancava!)
            '1.3.14.3.2.26': hashes.SHA1(),
            '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
            '2.16.840.1.101.3.4.2.3': hashes.SHA512(), # <--- Ecco il tuo colpevole!
            '2.16.840.1.101.3.4.2.4': hashes.SHA224(),
        }

    def _calc_hash(self, file_path, algo_name):
        """Calcola hash di un file locale"""
        if algo_name not in self.algo_map:
            algo_name = algo_name.replace("-", "").lower()
            if algo_name not in self.algo_map:
                raise ValueError(f"Algoritmo hash sconosciuto: {algo_name}")
        
        digest = hashes.Hash(self.algo_map[algo_name], backend=default_backend())
        with open(file_path, "rb") as f:
            digest.update(f.read())
        return digest.finalize()
    
    def _unwrap_sod(self, raw_data):
        """Pulisce il SOD rimuovendo wrapper ICAO (Tag 0x77)."""
        if not raw_data: return raw_data
        
        # Se inizia con 0x30, è già pulito
        if raw_data[0] == 0x30: return raw_data
        
        # Se inizia con 0x77, spacchettiamo
        if raw_data[0] == 0x77:
            print("   ⚠️  Rilevato Wrapper 0x77. Rimozione in corso...")
            idx = 1
            if raw_data[idx] < 0x80:
                length = raw_data[idx]
                idx += 1
            else:
                num_len_bytes = raw_data[idx] & 0x7f
                idx += 1 + num_len_bytes # Salta bytes lunghezza
            
            # Cerca tag 0x82 o 0x30
            if idx < len(raw_data) and raw_data[idx] == 0x82:
                print("   ⚠️  Rilevato Tag 0x82 (Response Data). Rimozione...")
                idx += 1 
                if raw_data[idx] < 0x80:
                    idx += 1
                else:
                    num_len_bytes = raw_data[idx] & 0x7f
                    idx += 1 + num_len_bytes
            
            return raw_data[idx:]

        return raw_data

    def run(self):
        print("\n=== AVVIO PASSIVE AUTHENTICATION ===")
        
        # --- CARICAMENTO E PULIZIA SOD ---
        try:
            with open(self.sod_path, 'rb') as f: 
                sod_raw_dirty = f.read()
            
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
        # STEP 1: VERIFICA INTEGRITÀ (HASH DEI DATAGROUPS)
        # ---------------------------------------------------------
        print("\n--- 1. VERIFICA INTEGRITÀ DATI ---")
        try:
            encap_content = signed_data['encap_content_info']['content'].native
            lds_obj = LDSSecurityObject.load(encap_content)
            
            sod_algo = lds_obj['hash_algorithm']['algorithm'].native
            print(f"[*] Algoritmo Hash Passaporto: {sod_algo}")
            
            stored_hashes = {item['data_group_number'].native: item['data_group_hash_value'].native 
                             for item in lds_obj['datagroup_hash_values']}

            # Verifica DG1
            if 1 in stored_hashes:
                calc_dg1 = self._calc_hash(self.dg1_path, sod_algo)
                if calc_dg1 == stored_hashes[1]:
                    print("✅ DG1 INTEGRITY: OK")
                else:
                    print(f"❌ DG1 INTEGRITY: FALLITA!")
                    return 
            
            # Verifica DG2
            if 2 in stored_hashes:
                calc_dg2 = self._calc_hash(self.dg2_path, sod_algo)
                if calc_dg2 == stored_hashes[2]:
                    print("✅ DG2 INTEGRITY: OK")
                else:
                    print("❌ DG2 INTEGRITY: FALLITA!")
                    return
                    
        except Exception as e:
            print(f"❌ Errore durante Hash Check: {e}")
            return

        # ---------------------------------------------------------
        # STEP 2: VERIFICA FIRMA SOD (DOCUMENT SIGNER)
        # ---------------------------------------------------------
        print("\n--- 2. VERIFICA FIRMA DIGITALE SOD ---")
        try:
            # A. Estrarre Certificato DS
            certs = signed_data['certificates']
            ds_cert_x509 = certs[0].chosen
            self.ds_cert = ds_cert_x509.dump()
            
            ds_cert_crypto = load_der_x509_certificate(self.ds_cert, default_backend())
            ds_pub_key = ds_cert_crypto.public_key()
            
            # B. Estrarre Info Firma e Attributi
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            # C. PREPARAZIONE PAYLOAD (FIX ASN.1)
            # Qui usiamo la libreria per ricostruire il 'SET OF' corretto
            try:
                raw_attrs = signer_info['signed_attrs']
                clean_attrs = cms.CMSAttributes(raw_attrs.native)
                payload_to_verify = clean_attrs.dump()
                
                # Check difensivo
                if payload_to_verify[0] != 0x31:
                    print(f"⚠️ Warning: Payload non inizia con 0x31 (Hex: {hex(payload_to_verify[0])})")
            except Exception as e:
                print(f"❌ Errore preparazione payload firma: {e}")
                return

            # D. Recupero Algoritmo Hash Firma
            sig_algo = signer_info['digest_algorithm']['algorithm'].native
            hash_algo_class = self.algo_map.get(sig_algo, hashes.SHA256()) # Default SHA256 se non trovato
            
            # E. Verifica Matematica
            try:
                if isinstance(ds_pub_key, rsa.RSAPublicKey):
                    try:
                        # Tentativo 1: PKCS1 v1.5
                        ds_pub_key.verify(signature, payload_to_verify, padding.PKCS1v15(), hash_algo_class)
                        print("✅ Firma SOD (RSA PKCS#1 v1.5): VALIDA")
                    except:
                        # Tentativo 2: PSS
                        ds_pub_key.verify(
                            signature, 
                            payload_to_verify, 
                            padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=padding.PSS.MAX_LENGTH),
                            hash_algo_class
                        )
                        print("✅ Firma SOD (RSA PSS): VALIDA")
                
                elif isinstance(ds_pub_key, ec.EllipticCurvePublicKey):
                    # ECDSA
                    ds_pub_key.verify(signature, payload_to_verify, ec.ECDSA(hash_algo_class))
                    print("✅ Firma SOD (ECDSA): VALIDA")
            
            except Exception as e:
                print(f"❌ Firma SOD NON VALIDA: {e}")
                return 

        except Exception as e:
            print(f"❌ Errore generale verifica firma: {e}")
            return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST (CSCA)
        # ---------------------------------------------------------
        print("\n--- 3. CHAIN OF TRUST (CSCA -> DS) ---")
        if not os.path.exists(self.csca_folder):
            print(f"⚠️ Cartella CSCA '{self.csca_folder}' non trovata. Impossibile validare la catena.")
            print("\n🎉 PASSAPORTO VALIDO INTERNAMENTE (Integrità + Firma Document Signer OK).")
            return

        ds_issuer = ds_cert_crypto.issuer
        print(f"[*] DS Issuer: {ds_issuer}")
        
        csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt','.pem','.der'))]
        found = False
        
        for c_file in csca_files:
            try:
                path = os.path.join(self.csca_folder, c_file)
                with open(path, 'rb') as f: data = f.read()
                
                try: csca = load_pem_x509_certificate(data, default_backend())
                except: csca = load_der_x509_certificate(data, default_backend())

                if csca.subject == ds_issuer:
                    csca_pub = csca.public_key()
                    try:
                        # Prova verifica generica (copre RSA PKCS1 e ECDSA)
                        csca_pub.verify(
                            ds_cert_crypto.signature,
                            ds_cert_crypto.tbs_certificate_bytes,
                            padding.PKCS1v15() if isinstance(csca_pub, rsa.RSAPublicKey) else ec.ECDSA(ds_cert_crypto.signature_hash_algorithm),
                            ds_cert_crypto.signature_hash_algorithm
                        )
                        print(f"   ✅ BINGO! Chain Validated con {c_file}")
                        found = True
                        break
                    except:
                         # Fallback PSS per RSA
                        if isinstance(csca_pub, rsa.RSAPublicKey):
                            try:
                                csca_pub.verify(
                                    ds_cert_crypto.signature,
                                    ds_cert_crypto.tbs_certificate_bytes,
                                    padding.PSS(mgf=padding.MGF1(ds_cert_crypto.signature_hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
                                    ds_cert_crypto.signature_hash_algorithm
                                )
                                print(f"   ✅ BINGO! Chain Validated (PSS) con {c_file}")
                                found = True
                                break
                            except: continue
            except: continue
        
        if not found:
            print("⚠️ Chain of Trust: Nessun certificato CSCA corrispondente trovato (Normale se non hai il Master List).")
        else:
            print("\n🎉 PASSAPORTO COMPLETAMENTE VALIDO E AUTENTICO.")

# ESECUZIONE
if __name__ == "__main__":
    # Percorsi relativi corretti per la struttura:
    # src/ (dove sei tu con lo script)
    # └── FILE/ (dove sono i .bin)
    
    # IMPORTANTE: Sostituisci i nomi dei file con quelli ESATTI che hai nella cartella FILE
    v = PassiveValidator(
        dg1_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG1.bin", 
        dg2_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG2.bin", 
        sod_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin", 
        csca_folder="./certs" 
    )
    v.run()