from asn1crypto import core
import sys

def print_mrz_data(mrz_text):
    """Formatta e stampa i dati MRZ (TD3 - Passaporto Standard)"""
    # Rimuoviamo spazi e newlines
    lines = mrz_text.strip().split('\n')
    lines = [l.strip() for l in lines if l.strip()]
    
    if not lines:
        print("Errore: Nessun dato MRZ trovato.")
        return

    print("-" * 40)
    print("   DATI ESTRATTI DA DG1 (Passaporto)")
    print("-" * 40)
    
    # Stampa grezza delle righe
    print(f"MRZ Riga 1: {lines[0]}")
    if len(lines) > 1:
        print(f"MRZ Riga 2: {lines[1]}")
    print("-" * 40)

    # Parsing (Assumendo formato Passaporto standard TD3 - 44 caratteri)
    # Se è una Carta d'Identità (TD1) la struttura è diversa (3 righe)
    
    try:
        line1 = lines[0]
        line2 = lines[1] if len(lines) > 1 else ""

        # RIGA 1
        doc_type = line1[0:2].replace('<', '')
        country = line1[2:5].replace('<', '')
        # Il nome inizia dal carattere 5 e finisce alla fine della riga
        # I nomi sono separati da <<
        names = line1[5:].split('<<')
        surname = names[0].replace('<', ' ').strip()
        name = names[1].replace('<', ' ').strip() if len(names) > 1 else ""

        # RIGA 2
        doc_num = line2[0:9].replace('<', '')
        nationality = line2[10:13].replace('<', '')
        dob = line2[13:19] # YYMMDD
        sex = line2[20]
        expiry = line2[21:27] # YYMMDD
        
        # Formattazione Date
        dob_fmt = f"{dob[4:6]}/{dob[2:4]}/19{dob[0:2]}" if int(dob[0:2]) > 50 else f"{dob[4:6]}/{dob[2:4]}/20{dob[0:2]}"
        exp_fmt = f"{expiry[4:6]}/{expiry[2:4]}/20{expiry[0:2]}"

        print(f"Cognome:       {surname}")
        print(f"Nome:          {name}")
        print(f"Nazione:       {country} ({nationality})")
        print(f"Documento:     {doc_num}")
        print(f"Sesso:         {sex}")
        print(f"Data Nascita:  {dob_fmt}")
        print(f"Scadenza:      {exp_fmt}")
        
    except Exception as e:
        print(f"Nota: Parsing automatico fallito (formato non standard?): {e}")
        print("Vedi le righe MRZ grezze sopra.")

def main():
    try:
        with open("dg1.bin", "rb") as f:
            data = f.read()
            
        # Il DG1 è una struttura ASN.1.
        # Di solito contiene un Tag 61 -> Tag 5F1F -> Stringa MRZ
        
        # Metodo "brutale" ma efficace: Cerchiamo l'inizio dell'MRZ
        # L'MRZ inizia quasi sempre con 'P<' (passaporto) o 'I<' (carta identità)
        # o 'A<' / 'C<'. Cerchiamo la sequenza di byte ASCII.
        
        content = data.decode('latin1', errors='ignore')
        
        # Pulizia caratteri non stampabili per trovare il testo
        import re
        # Cerca stringhe lunghe di caratteri maiuscoli, numeri e <
        found = re.findall(r'[A-Z0-9<]{30,}', content)
        
        if found:
            # Uniamo le righe trovate
            full_mrz = "\n".join(found)
            print_mrz_data(full_mrz)
        else:
            print("Non sono riuscito a trovare stringhe MRZ nel file.")
            print("Dump grezzo:")
            print(content)

    except FileNotFoundError:
        print("❌ File dg1.bin non trovato.")

if __name__ == "__main__":
    main()