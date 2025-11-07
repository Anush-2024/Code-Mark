from faker import Faker
import csv, os, random

# Initialize Faker with Nordic + English locales
fake = Faker(['en_US', 'sv_SE', 'da_DK'])
os.makedirs("sample_data", exist_ok=True)

# === 1️⃣ Generate Structured Patient Data (patients.csv) ===
with open("sample_data/patients.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["Name", "CPR", "Email", "Diagnosis", "Notes"])
    for _ in range(100):
        w.writerow([
            fake.name(),
            fake.bothify("######-####"),
            fake.email(),
            fake.random_element(["Diabetes", "Asthma", "Hypertension"]),
            fake.sentence(nb_words=8)
        ])

# === 2️⃣ Generate Unstructured Log Data (logs.txt) ===
log_entries = []
for _ in range(50):
    name = fake.name()
    cpr = fake.bothify("######-####")
    hospital = fake.random_element(["Aarhus Hospital", "Karolinska", "Oslo Med Center"])
    diagnosis = fake.random_element(["Diabetes", "Asthma", "Hypertension"])
    
    log_entries.append(
        f"[INFO] Appointment booked for {name} (CPR {cpr}) at {hospital}. Diagnosis: {diagnosis}\n"
    )

with open("sample_data/logs.txt", "w", encoding="utf-8") as f:
    f.writelines(log_entries)

print("✅ Generated synthetic healthcare data:")
print("   - sample_data/patients.csv")
print("   - sample_data/logs.txt")
