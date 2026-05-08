import json
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight

RAW_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty",
]

# 0=Normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R
CATEGORY_MAP = {
    "normal": 0,
    # DoS
    "back":1,"land":1,"neptune":1,"pod":1,"smurf":1,
    "teardrop":1,"apache2":1,"udpstorm":1,"processtable":1,"worm":1,
    # Probe
    "ipsweep":2,"nmap":2,"portsweep":2,"satan":2,"mscan":2,"saint":2,
    # R2L
    "ftp_write":3,"guess_passwd":3,"imap":3,"multihop":3,"phf":3,
    "spy":3,"warezclient":3,"warezmaster":3,"sendmail":3,"named":3,
    "snmpgetattack":3,"snmpguess":3,"xlock":3,"xsnoop":3,"httptunnel":3,
    # U2R
    "buffer_overflow":4,"loadmodule":4,"perl":4,"rootkit":4,
    "ps":4,"sqlattack":4,"xterm":4,
}

CATEGORY_NAMES = {0:"Normal", 1:"DoS", 2:"Probe", 3:"R2L", 4:"U2R"}

with open("encoder_mapping.json") as f:
    enc_map = json.load(f)

with open("feature_columns.json") as f:
    feature_columns = json.load(f)

print("KDDTrain+ yukleniyor...")
df = pd.read_csv("KDDTrain+.txt", names=RAW_COLUMNS)
df = df.drop(columns=["difficulty"])

for col in ["protocol_type", "service", "flag"]:
    df[col] = df[col].astype(str).map(enc_map[col]).fillna(0).astype(int)

df["category"] = df["label"].astype(str).map(CATEGORY_MAP)
df = df.dropna(subset=["category"])
df["category"] = df["category"].astype(int)

X = df[feature_columns].replace([np.inf, -np.inf], np.nan)
y = df["category"]

print(f"Sinif dagilimi:\n{y.value_counts().rename(CATEGORY_NAMES)}\n")

imputer = joblib.load("imputer.pkl")
scaler  = joblib.load("scaler.pkl")
X_imp    = imputer.transform(X)
X_scaled = scaler.transform(X_imp)

X_train, X_val, y_train, y_val = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print("Model egitiliyor...")
model = XGBClassifier(
    objective="multi:softmax",
    num_class=5,
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="mlogloss",
    random_state=42,
    n_jobs=-1,
)
sample_weights = compute_sample_weight("balanced", y_train)
model.fit(X_train, y_train, sample_weight=sample_weights)

preds = model.predict(X_val)
print("\nSiniflandirma Raporu:")
print(classification_report(y_val, preds, target_names=list(CATEGORY_NAMES.values())))

joblib.dump(model, "xgboost_multiclass.pkl")
with open("category_names.json", "w") as f:
    json.dump(CATEGORY_NAMES, f)

# --- Multiclass confusion matrix kaydet ---
labels = list(CATEGORY_NAMES.values())
cm = confusion_matrix(y_val, preds)
fig, ax = plt.subplots(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=labels, yticklabels=labels, ax=ax)
ax.set_title("Confusion Matrix - Multiclass (DoS/Probe/R2L/U2R)")
ax.set_xlabel("Tahmin")
ax.set_ylabel("Gerçek")
plt.tight_layout()
plt.savefig("confusion_matrix_multiclass.png", dpi=100)
plt.close()
print("Kaydedildi: xgboost_multiclass.pkl, category_names.json, confusion_matrix_multiclass.png")
