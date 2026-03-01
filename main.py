import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle
import os

print(" Chargement des données...")

# Noms des colonnes
colonnes = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

# Charger les données
df = pd.read_csv('data/KDDTrain.txt', header=None, names=colonnes)
print(f" {df.shape[0]} lignes chargées !")

# Étape 2 — Préparer les données
print("\n Préparation des données...")

# Convertir les colonnes texte en nombres
le = LabelEncoder()
df['protocol_type'] = le.fit_transform(df['protocol_type'])
df['service'] = le.fit_transform(df['service'])
df['flag'] = le.fit_transform(df['flag'])

# Garder seulement les colonnes numériques utiles
features = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'serror_rate', 'rerror_rate', 'same_srv_rate',
    'dst_host_count', 'dst_host_srv_count'
]

X = df[features]

# Normaliser les données
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print(" Données préparées !")

# Étape 3 — Entraîner le modèle
print("\n Entraînement du modèle ML...")
model = IsolationForest(
    contamination=0.1,
    random_state=42,
    n_estimators=100
)
model.fit(X_scaled)
print(" Modèle entraîné !")

# Étape 4 — Tester le modèle
print("\n Test du modèle...")
predictions = model.predict(X_scaled[:100])
normaux = sum(1 for p in predictions if p == 1)
attaques = sum(1 for p in predictions if p == -1)
print(f"Sur 100 connexions testées :")
print(f" Normales : {normaux}")
print(f"  Attaques détectées : {attaques}")

# Étape 5 — Sauvegarder le modèle
print("\n Sauvegarde du modèle...")
os.makedirs('models', exist_ok=True)
pickle.dump(model, open('models/model.pkl', 'wb'))
pickle.dump(scaler, open('models/scaler.pkl', 'wb'))
pickle.dump(features, open('models/features.pkl', 'wb'))
print(" Modèle sauvegardé dans le dossier models/ !")




