import os
import hashlib
from asn1crypto import cms, x509, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# --- DEFINIZIONI STRUTTURE ASN.1 (ICAO 9303) ---
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
            # OID Numerici (Indispensabili per il tuo passaporto)
            '1.3.14.3.2.26': hashes.SHA1(),
            '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
            '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
            '2.16.840.1.101.3.4.2.3': hashes.SHA512(), 
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
        if raw_data[0] == 0x30: return raw_data # Già pulito
        
        if raw_data[0] == 0x77:
            print("   ⚠️  Rilevato Wrapper 0x77. Rimozione in corso...")
            idx = 1
            if raw_data[idx] < 0x80:
                length = raw_data[idx]
                idx += 1
            else:
                num_len_bytes = raw_data[idx] & 0x7f
                idx += 1 + num_len_bytes
            
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
        print(f"Cartella CSCA: {self.csca_folder}")
        
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
        print("\n--- 1. VERIFICA INTEGRITÀ DATI (Passive Auth - Step A) ---")
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
                    print("✅ DG1 INTEGRITY: OK (Dati Anagrafici integri)")
                else:
                    print(f"❌ DG1 INTEGRITY: FALLITA!")
                    return 
            
            # Verifica DG2
            if 2 in stored_hashes:
                calc_dg2 = self._calc_hash(self.dg2_path, sod_algo)
                if calc_dg2 == stored_hashes[2]:
                    print("✅ DG2 INTEGRITY: OK (Foto biometrica integra)")
                else:
                    print("❌ DG2 INTEGRITY: FALLITA!")
                    return
                    
        except Exception as e:
            print(f"❌ Errore durante Hash Check: {e}")
            return

        # ---------------------------------------------------------
        # STEP 2: VERIFICA FIRMA SOD (DOCUMENT SIGNER)
        # ---------------------------------------------------------
        print("\n--- 2. VERIFICA FIRMA DIGITALE SOD (Passive Auth - Step B) ---")
        try:
            # A. Estrarre Certificato DS
            certs = signed_data['certificates']
            ds_cert_x509 = certs[0].chosen
            self.ds_cert = ds_cert_x509.dump()
            
            ds_cert_crypto = load_der_x509_certificate(self.ds_cert, default_backend())
            ds_pub_key = ds_cert_crypto.public_key()
            
            # B. Estrarre Info Firma
            signer_info = signed_data['signer_infos'][0]
            signature = signer_info['signature'].native
            
            # C. Preparazione Payload (Metodo Byte Patching)
            try:
                raw_bytes = signer_info['signed_attrs'].dump()
                payload_as_array = bytearray(raw_bytes)
                
                # Patch Tag da A0 a 31 (Cruciale per la verifica)
                if payload_as_array[0] == 0xA0:
                    payload_as_array[0] = 0x31
                    payload_to_verify = bytes(payload_as_array)
                else:
                    payload_to_verify = raw_bytes
            except Exception as e:
                print(f"❌ Errore preparazione payload: {e}")
                return

            # D. Recupero Algoritmo Hash Firma
            try:
                sig_algo_oid = signer_info['digest_algorithm']['algorithm'].native
                hash_algo_class = self.algo_map.get(sig_algo_oid, hashes.SHA256()) 
            except:
                sig_algo_oid = "Sconosciuto"
                hash_algo_class = hashes.SHA256()

            # --- PROOF PER IL PROFESSORE ---
            print("\n   🔎 DETTAGLI TECNICI ESTRATTI (PROOF OF WORK):")
            print(f"   ► DS Subject: {ds_cert_crypto.subject}")
            print(f"   ► DS Serial Number: {ds_cert_crypto.serial_number}")
            print(f"   ► Algoritmo Firma: {sig_algo_oid}")
            
            # Calcoliamo l'hash dei dati che stiamo per verificare
            # Questo dimostra che abbiamo processato il payload
            hasher = hashes.Hash(hash_algo_class, backend=default_backend())
            hasher.update(payload_to_verify)
            digest = hasher.finalize()
            print(f"   ► Hash Calcolato (primi 20 byte): {digest.hex()[:40]}...")
            print("   -------------------------------------------------")

            # E. Verifica Matematica
            try:
                if isinstance(ds_pub_key, ec.EllipticCurvePublicKey):
                    ds_pub_key.verify(signature, payload_to_verify, ec.ECDSA(hash_algo_class))
                    print("✅ Firma SOD (ECDSA): VALIDA")

                elif isinstance(ds_pub_key, rsa.RSAPublicKey):
                    # TENTATIVO 1: RSA-PSS con Salt AUTO (Standard Moderno)
                    try:
                        ds_pub_key.verify(
                            signature, 
                            payload_to_verify, 
                            padding.PSS(mgf=padding.MGF1(hash_algo_class), salt_length=padding.PSS.AUTO),
                            hash_algo_class
                        )
                        print("✅ Firma SOD (RSA PSS - Auto Salt): VALIDA")
                    except:
                        # TENTATIVO 2: PKCS1 v1.5 (Standard Vecchio)
                        ds_pub_key.verify(signature, payload_to_verify, padding.PKCS1v15(), hash_algo_class)
                        print("✅ Firma SOD (RSA PKCS#1 v1.5): VALIDA")
            
            except Exception as e:
                print(f"❌ Firma SOD NON VALIDA. Tutti i tentativi falliti.")
                print(f"   Ultimo errore: {e}")
                return 

        except Exception as e:
            print(f"❌ Errore generale verifica firma: {e}")
            return

        # ---------------------------------------------------------
        # STEP 3: CHAIN OF TRUST (CSCA)
        # ---------------------------------------------------------
        print("\n--- 3. CHAIN OF TRUST (CSCA -> Document Signer) ---")
        if not os.path.exists(self.csca_folder):
            print(f"⚠️ Cartella CSCA '{self.csca_folder}' non trovata.")
            return

        ds_issuer = ds_cert_crypto.issuer
        print(f"[*] DS Emesso da: {ds_issuer}")
        print(f"[*] Ricerca certificato 'parent' nella cartella '{self.csca_folder}'...")
        
        # Scansione file
        csca_files = [f for f in os.listdir(self.csca_folder) if f.lower().endswith(('.cer','.crt','.pem','.der'))]
        found = False
        
        for c_file in csca_files:
            try:
                path = os.path.join(self.csca_folder, c_file)
                with open(path, 'rb') as f: data = f.read()
                
                # Tentativo caricamento (gestisce sia DER binario che PEM testuale)
                try: csca = load_pem_x509_certificate(data, default_backend())
                except: csca = load_der_x509_certificate(data, default_backend())

                # Controllo se è il genitore (Issuer == Subject)
                if csca.subject == ds_issuer:
                    print(f"   🔎 Candidato trovato: {c_file}")
                    csca_pub = csca.public_key()
                    
                    try:
                        # Verifica Firma del Certificato DS usando la chiave CSCA
                        # Prova verifica generica (copre RSA PKCS1 e ECDSA)
                        csca_pub.verify(
                            ds_cert_crypto.signature,
                            ds_cert_crypto.tbs_certificate_bytes,
                            padding.PKCS1v15() if isinstance(csca_pub, rsa.RSAPublicKey) else ec.ECDSA(ds_cert_crypto.signature_hash_algorithm),
                            ds_cert_crypto.signature_hash_algorithm
                        )
                        print(f"   ✅ BINGO! Chain of Trust validata con {c_file}")
                        found = True
                        break
                    except Exception as e:
                        # Fallback PSS per RSA (se il CSCA usa PSS per firmare i DS)
                        if isinstance(csca_pub, rsa.RSAPublicKey):
                            try:
                                csca_pub.verify(
                                    ds_cert_crypto.signature,
                                    ds_cert_crypto.tbs_certificate_bytes,
                                    padding.PSS(mgf=padding.MGF1(ds_cert_crypto.signature_hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
                                    ds_cert_crypto.signature_hash_algorithm
                                )
                                print(f"   ✅ BINGO! Chain of Trust validata (PSS) con {c_file}")
                                found = True
                                break
                            except: 
                                print(f"   ❌ Firma non valida su {c_file} ({e})")
            except: 
                continue
        
        if not found:
            print("❌ Chain of Trust FALLITA: Nessun CSCA valido trovato nella cartella.")
            print("   Suggerimento: Controlla di avere il file .cer corretto (es. CSCA04.cer o CSCA05.cer)")
        else:
            print("\n🎉 PASSAPORTO COMPLETAMENTE VALIDO, AUTENTICO E FIDATO.")

# ESECUZIONE
if __name__ == "__main__":
    # CONFIGURAZIONE PERCORSI
    # Assicurati che le cartelle FILE e certs esistano
    v = PassiveValidator(
        dg1_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG1.bin", 
        dg2_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-DG2.bin", 
        sod_path="../FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin", 
        csca_folder="../certs" # Punta alla cartella con i file .cer
    )
    v.run()