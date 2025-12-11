# Salva questo come clean_sod.py nella cartella src
from verify import PassiveValidator # Importa la tua classe dal file verify.py che abbiamo fatto

# Metti il nome del TUO file SOD attuale
sod_path = "FILE/YC60963196ITA7005107M3407149<<<<<<<<<<<<<<02-SOD.bin"

with open(sod_path, 'rb') as f:
    raw = f.read()

# Usa la funzione che funzionava bene per pulire il 77/82
v = PassiveValidator(None, None, None, None)
clean_data = v._unwrap_sod(raw)

with open("sod_clean.bin", "wb") as f:
    f.write(clean_data)
    print("Salvato sod_clean.bin (pronto per OpenSSL!)")