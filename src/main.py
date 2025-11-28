import os
from validator import PassiveAuthValidator

# Settimana prossima, queste funzioni useranno pyscard/pypassport
def read_passport_simulated():
    ## da capire come farlo con pypassport!!!
    ## NFC reader --> su ubuntu??

def main():
    print("--- ePassport Passive Authentication Tool ---")
    
    try:
        # 1. ACQUISIZIONE DATI
        sod_data, dg1_data = read_passport_simulated()
        
        # 2. VERIFICA
        validator = PassiveAuthValidator(sod_data, dg1_data)
        
        validator.verify_integrity()  # Hash check
        validator.verify_signature_with_openssl()  # DS check
        validator.verify_chain()      # CSCA check
        
        print("\n[V] PASSAPORTO VALIDO E AUTENTICO.")
        
    except Exception as e:
        print(f"\n[X] ERRORE VALIDAZIONE: {e}")

if __name__ == "__main__":
    main()