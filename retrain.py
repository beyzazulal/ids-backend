import os
import json
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from pymongo import MongoClient

MONGO_URI    = os.environ.get("IDS_MONGO_URI",    "mongodb://localhost:27017/")
COLUMNS_PATH = os.environ.get("IDS_COLUMNS_PATH", "feature_columns.json")
TRAIN_DATA   = os.environ.get("IDS_TRAIN_DATA",   "KDDTrain+.txt")
MODEL_PATH   = os.environ.get("IDS_MODEL_PATH",   "xgboost_ids_final.pkl")
IMPUTER_PATH = os.environ.get("IDS_IMPUTER_PATH", "imputer.pkl")
SCALER_PATH  = os.environ.get("IDS_SCALER_PATH",  "scaler.pkl")

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

with open(COLUMNS_PATH) as f:
    feature_columns = json.load(f)

with open("encoder_mapping.json") as f:
    enc_map = json.load(f)


def _load_train():
    df = pd.read_csv(TRAIN_DATA, names=RAW_COLUMNS)
    df = df.drop(columns=["difficulty"])
    for col in ["protocol_type", "service", "flag"]:
        df[col] = df[col].astype(str).map(enc_map[col]).fillna(0).astype(int)
    return df


def retrain():
    # --- base dataset (KDDTrain) ---
    base_df = _load_train()
    base_X  = base_df[feature_columns].replace([np.inf, -np.inf], np.nan)
    base_y  = (base_df["label"] != "normal").astype(int)

    # --- feedback from MongoDB ---
    client         = MongoClient(MONGO_URI)
    collection     = client["ids_project"]["feedback_samples"]
    docs           = list(collection.find({}, {"_id": 0}))
    feedback_count = len(docs)

    if docs:
        fb_df = pd.DataFrame(docs)
        fb_X  = fb_df.reindex(columns=feature_columns, fill_value=0).replace([np.inf, -np.inf], np.nan)
        fb_y  = fb_df["true_label"].astype(int)
        X_all = pd.concat([base_X, fb_X], ignore_index=True)
        y_all = pd.concat([base_y, fb_y], ignore_index=True)
    else:
        X_all = base_X
        y_all = base_y

    # --- preprocess with existing imputer/scaler ---
    imputer  = joblib.load(IMPUTER_PATH)
    scaler   = joblib.load(SCALER_PATH)
    X_imp    = imputer.transform(X_all)
    X_scaled = scaler.transform(X_imp)

    stratify = y_all if y_all.nunique() > 1 else None
    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled, y_all, test_size=0.2, random_state=42, stratify=stratify
    )

    # --- evaluate old model before overwriting ---
    old_model = joblib.load(MODEL_PATH)
    old_preds = old_model.predict(X_val)
    before_fn = int(((y_val == 1) & (old_preds == 0)).sum())
    before_f1 = float(f1_score(y_val, old_preds))

    # --- train new model ---
    new_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    new_model.fit(X_train, y_train)

    new_preds = new_model.predict(X_val)
    after_fn  = int(((y_val == 1) & (new_preds == 0)).sum())
    after_f1  = float(f1_score(y_val, new_preds))

    # --- persist ---
    joblib.dump(new_model, MODEL_PATH)

    results = {
        "before_fn":      before_fn,
        "before_f1":      before_f1,
        "after_fn":       after_fn,
        "after_f1":       after_f1,
        "feedback_count": feedback_count,
    }
    with open("retraining_results.json", "w") as f:
        json.dump(results, f)

    return results


if __name__ == "__main__":
    r = retrain()
    print("Retraining tamamlandi:", r)
