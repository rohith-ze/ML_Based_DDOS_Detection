import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load datasets
df_ddos = pd.read_csv("/media/rohith/windows/vscode/DDos_Malware_detection/cicddos2019_dataset.csv", on_bad_lines='warn')
#df_kdd = pd.read_csv("/media/rohith/windows/vscode/DDos_Malware_detection/KDD.csv")
df_malware = pd.read_csv("DDos_Malware_detection/dataset_malwares.csv")

# Remove unwanted columns
df_ddos.drop(columns=['Unnamed: 0'], errors='ignore', inplace=True)

# Handle missing values
df_ddos.dropna(inplace=True)
#df_kdd.dropna(inplace=True)
df_malware.dropna(inplace=True)

# Encode categorical labels
label_encoder = LabelEncoder()
df_ddos['Label'] = label_encoder.fit_transform(df_ddos['Label'])
#df_kdd['class'] = label_encoder.fit_transform(df_kdd['class'])
df_malware['Malware'] = label_encoder.fit_transform(df_malware['Malware'])

# Select relevant features for training

# ✅ **DDoS Attack Detection Features**
features_ddos = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow Bytes/s',
    'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count'
]
X_ddos = df_ddos[features_ddos]
y_ddos = df_ddos['Label']
'''
# ✅ **KDD Dataset Features**
features_kdd = [
    'duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate'
]
X_kdd = df_kdd[features_kdd]
y_kdd = df_kdd['class']
'''
# ✅ **Malware Dataset Features**
features_malware = [
    'MajorOperatingSystemVersion', 'MajorSubsystemVersion', 'ImageBase',
    'SizeOfImage', 'Subsystem', 'DllCharacteristics', 'SuspiciousImportFunctions',
    'SuspiciousNameSection', 'SectionMinEntropy', 'SectionMaxEntropy'
]
X_malware = df_malware[features_malware]
y_malware = df_malware['Malware']

# Train-Test Split
X_train_ddos, X_test_ddos, y_train_ddos, y_test_ddos = train_test_split(X_ddos, y_ddos, test_size=0.2, random_state=42)
#X_train_kdd, X_test_kdd, y_train_kdd, y_test_kdd = train_test_split(X_kdd, y_kdd, test_size=0.2, random_state=42)
X_train_malware, X_test_malware, y_train_malware, y_test_malware = train_test_split(X_malware, y_malware, test_size=0.2, random_state=42)

# Train Models
rf_ddos = RandomForestClassifier(n_estimators=200, random_state=42)
rf_ddos.fit(X_train_ddos, y_train_ddos)

#rf_kdd = RandomForestClassifier(n_estimators=200, random_state=42)
#rf_kdd.fit(X_train_kdd, y_train_kdd)

rf_malware = RandomForestClassifier(n_estimators=200, random_state=42)
rf_malware.fit(X_train_malware, y_train_malware)

# Save Models
joblib.dump(rf_ddos, "/media/rohith/windows/vscode/DDos_Malware_detection/ddos2/MODELS/rf_ddos_model.pkl")
#joblib.dump(rf_kdd, "/media/rohith/windows/vscode/DDos_Malware_detection/ddos2/MODELS/rf_kdd_model.pkl")
joblib.dump(rf_malware, "/media/rohith/windows/vscode/DDos_Malware_detection/ddos2/MODELS/rf_malware_model.pkl")

# Evaluate Models
def evaluate_model(model, X_test, y_test, model_name):
    y_pred = model.predict(X_test)
    print(f"\n🔹 {model_name} Model Performance:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))
    sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d', cmap="Blues")
    plt.show()

evaluate_model(rf_ddos, X_test_ddos, y_test_ddos, "DDoS")
#evaluate_model(rf_kdd, X_test_kdd, y_test_kdd, "KDD Intrusion")
evaluate_model(rf_malware, X_test_malware, y_test_malware, "Malware Detection")