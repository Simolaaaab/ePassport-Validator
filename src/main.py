import os
from validator import PassiveAuthValidator

# Settimana prossima, queste funzioni useranno pyscard/pypassport
def read_passport_simulated():
    # MOCK: Fingiamo di aver letto il chip
    if not os.path.exists("EF_SOD.bin"):
        raise FileNotFoundError("Collega il lettore o fornisci file di dump!")
    
    with open("EF_SOD.bin", "rb") as f:
        sod = f.read()
    with open("EF_DG1.bin", "rb") as f:
        dg1 = f.read()
    return sod, dg1

def main():
    print("--- ePassport Passive Authentication Tool ---")
    
    try:
        # 1. ACQUISIZIONE DATI
        sod_data, dg1_data = read_passport_simulated()
        
        # 2. VERIFICA
        validator = PassiveAuthValidator(sod_data, dg1_data)
        
        validator.verify_integrity()  # Hash check
        validator.verify_signature()  # DS check
        validator.verify_chain()      # CSCA check
        
        print("\n[V] PASSAPORTO VALIDO E AUTENTICO.")
        
    except Exception as e:
        print(f"\n[X] ERRORE VALIDAZIONE: {e}")

if __name__ == "__main__":
    main()