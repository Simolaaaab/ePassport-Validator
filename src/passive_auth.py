import os
import hashlib
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# --- DEFINIZIONI ASN.1 (Per leggere il SOD) ---
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
        }

    def _calc_hash(self, file_path, algo_name):
        """Calcola hash di un file locale"""
        if algo_name not in self.algo_map:
            # Fallback comune: a volte asn1crypto ritorna nomi leggermente diversi
            algo_name = algo_name.replace("-", "").lower()
            if algo_name not in self.algo_map:
                raise ValueError(f"Algoritmo hash sconosciuto: {algo_name}")
        
        digest = hashes.Hash(self.algo_map[algo_name], backend=default_backend())
        with open(file_path, "rb") as f:
            digest.update(f.read())
        return digest.finalize()
    
    def _unwrap_sod(self, raw_data):
        """
        Pulisce il SOD rimuovendo eventuali wrapper ICAO (Tag 0x77).
        """
        if not raw_data:
            return raw_data

        # Debug: Stampa i primi byte per capire cosa stiamo leggendo
        print(f"[*] SOD First Bytes: {raw_data[:8].hex().upper()}")

        # Se inizia con 0x30, è già pulito (Standard ASN.1 Sequence)
        if raw_data[0] == 0x30:
            return raw_data
        
        # Se inizia con 0x77 (Response Message Template), dobbiamo spacchettarlo
        if raw_data[0] == 0x77:
            print("   ⚠️  Rilevato Wrapper 0x77. Rimozione in corso...")
            idx = 1
            
            # Parsing Lunghezza Wrapper
            if raw_data[idx] < 0x80:
                length = raw_data[idx]
                idx += 1
            else:
                num_len_bytes = raw_data[idx] & 0x7f
                idx += 1
                length = int.from_bytes(raw_data[idx:idx + num_len_bytes], byteorder='big')
                idx += num_len_bytes
            
            # Ora siamo dentro il contenuto del 0x77.
            # Spesso troviamo un altro tag: 0x82 (Response Data) o direttamente il 0x30
            if idx < len(raw_data) and raw_data[idx] == 0x82:
                # Caso standard ICAO: 77 ... 82 ... [DATA]
                print("   ⚠️  Rilevato Tag 0x82 (Response Data). Rimozione...")
                idx += 1 # Salta 0x82
                
                # Parsing Lunghezza del 0x82
                if raw_data[idx] < 0x80:
                    idx += 1
                else:
                    num_len_bytes = raw_data[idx] & 0x7f
                    idx += 1 + num_len_bytes
            
            # Restituiamo tutto da qui in poi
            clean_data = raw_data[idx:]
            
            # Controllo finale
            if clean_data[0] != 0x30:
                print(f"   ❌ ATTENZIONE: Anche dopo l'unwrap, il file inizia con {hex(clean_data[0])} invece di 0x30!")
            else:
                print("   ✅ SOD pulito con successo.")
                
            return clean_data

        print("   ❌ Formato SOD sconosciuto (Non inizia con 30 né 77)")
        return raw_data

    def run(self):
        print("\n=== AVVIO PASSIVE AUTHENTICATION ===")
        
        # 1. Caricamento SOD
        try:
            with open(self.sod_path, 'rb') as f: 
                sod_raw_dirty = f.read()
            
            # >>> FIX QUI: PULIZIA DEL FILE <<<
            sod_raw = self._unwrap_sod(sod_raw_dirty)
            
            content_info = cms.ContentInfo.load(sod_raw)
            if content_info['content_type'].native != 'signed_data':
                print("❌ Errore: Il SOD non è un SignedData.")
                return
            signed_data = content_info['content']
            
        except Exception as e:
            print(f"❌ Errore parsing SOD: {e}")
            # Debug extra:
            import traceback
            traceback.print_exc()
            return
        # ---------------------------------------------------------
        # STEP 1: VERIFICA INTEGRITÀ (HASH DEI DATAGROUPS)
        # ---------------------------------------------------------
        print("\n--- 1. VERIFICA INTEGRITÀ DATI ---")
        try:
            encap_content = signed_data['encap_content_info']['content'].native
            lds_obj = LDSSecurityObject.load(encap_content)
            
            # Algoritmo usato nel SOD (es. sha256)
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
                    print(f"   Atteso: {stored_hashes[1].hex()[:10]}...")
                    print(f"   Calcolato: {calc_dg1.hex()[:10]}...")
                    return # Stop se i dati sono alterati
            
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
            # Estrazione Certificato DS interno
            certs = signed_data['certificates']
            # Prendiamo il primo certificato trovato (di solito è il DS)
            ds_cert_x509 = certs[0].chosen
            self.ds_cert = ds_cert_x509.dump()
            
            # Convertiamo in oggetto Cryptography per calcoli matematici
            ds_cert_crypto = load_der_x509_certificate(self.ds_cert, default_backend())
            ds_pub_key = ds_cert_crypto.public_key()
            
            # Dati da verificare: NON è il file intero, ma gli attributi firmati (SignedAttributes)
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            # Costruzione payload firmato (trick ASN.1: serve il DER dei signed_attrs ma con tag SET OF)
            # asn1crypto lo fa correttamente se dumpiano l'oggetto signed_attrs
            signed_attrs = signer_info['signed_attrs']
            payload_to_verify = signed_attrs.dump()
            
            # Check se il primo byte è corretto (deve essere 0x31 per SET OF)
            # A volte asn1crypto mantiene il context tag [0], dobbiamo forzare 0x31
            if payload_to_verify[0] != 0x31:
                payload_to_verify = b'\x31' + payload_to_verify[1:]

            # Recupero algoritmo hash della firma
            sig_algo = signer_info['digest_algorithm']['algorithm'].native
            hash_algo_class = self.algo_map.get(sig_algo, hashes.SHA256())

            # Verifica Matematica
            try:
                if isinstance(ds_pub_key, rsa.RSAPublicKey):
                    # TENTATIVO 1: PKCS1v15 (Standard passaporti vecchi)
                    try:
                        ds_pub_key.verify(signature, payload_to_verify, padding.PKCS1v15(), hash_algo_class)
                        print("✅ Firma SOD (RSA PKCS#1 v1.5): VALIDA")
                    except:
                        # TENTATIVO 2: PSS (Standard passaporti nuovi/tedeschi)
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
                print("   Il passaporto potrebbe essere clonato o il SOD corrotto.")
                return # Stop qui

        except Exception as e:
            print(f"❌ Errore parsing firma: {e}")
            return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST (CSCA)
        # ---------------------------------------------------------
        print("\n--- 3. CHAIN OF TRUST (CSCA -> DS) ---")
        if not os.path.exists(self.csca_folder):
            print(f"⚠️ Cartella {self.csca_folder} non trovata.")
            return

        ds_issuer = ds_cert_crypto.issuer
        print(f"[*] DS Issuer: {ds_issuer}")
        
        csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt','.pem','.der'))]
        found = False
        
        print(f"[*] Test su {len(csca_files)} certificati CSCA locali...")
        
        for c_file in csca_files:
            try:
                path = os.path.join(self.csca_folder, c_file)
                with open(path, 'rb') as f: data = f.read()
                
                # Load flessibile
                try: csca = load_pem_x509_certificate(data, default_backend())
                except: csca = load_der_x509_certificate(data, default_backend())

                if csca.subject == ds_issuer:
                    print(f"   🔎 Test candidato: {c_file}...")
                    csca_pub = csca.public_key()
                    
                    # Logica "Smart" per la verifica della firma del certificato
                    # Tentiamo PKCS1 v1.5 E PSS anche qui
                    try:
                        # Tenta verifica standard (cryptography gestisce padding base)
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
                        # Se fallisce e siamo su RSA, prova PSS esplicitamente
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
                            except:
                                continue # Prossimo file
            except:
                continue
        
        if not found:
            print("❌ Chain of Trust FALLITA: Nessun CSCA valido trovato.")
        else:
            print("\n🎉 PASSAPORTO VALIDO E AUTENTICO.")

# ESECUZIONE
if __name__ == "__main__":
    v = PassiveValidator("dg1.bin", "dg2.bin", "sod.bin", "./certs")
    v.run()