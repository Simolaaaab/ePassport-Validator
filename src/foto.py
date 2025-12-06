def extract_images_from_bin(filename):
    print(f"[*] Analisi file {filename} alla ricerca di immagini JPEG...")
    
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("❌ File non trovato. Scarica prima dg2.bin!")
        return

    # Magic Numbers JPEG: Inizia con FF D8, finisce con FF D9
    start_marker = b'\xFF\xD8'
    end_marker = b'\xFF\xD9'
    
    start_index = data.find(start_marker)
    
    if start_index != -1:
        # Cerca la fine a partire dall'inizio trovato
        end_index = data.find(end_marker, start_index)
        
        if end_index != -1:
            # Estraiamo i byte esatti dell'immagine (+2 per includere il marker di fine)
            jpg_data = data[start_index : end_index + 2]
            
            output_name = "foto_passaporto.jpg"
            with open(output_name, "wb") as out:
                out.write(jpg_data)
            
            print(f"✅ FOTO TROVATA! Salvata come: {output_name}")
            print(f"   Dimensione: {len(jpg_data)} bytes")
        else:
            print("❌ Trovato inizio JPEG, ma non la fine. File incompleto?")
    else:
        print("❌ Nessuna immagine JPEG trovata nel file (forse usa JPEG2000?).")

if __name__ == "__main__":
    extract_images_from_bin("dg2.bin")