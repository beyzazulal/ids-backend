
from flask import Flask, request, jsonify
from pymongo import MongoClient
import os
import traceback
import joblib
import json
import numpy as np
import pandas as pd
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# ===== Config =====
MODEL_PATH = os.environ.get("IDS_MODEL_PATH", "xgboost_ids_final.pkl")
IMPUTER_PATH = os.environ.get("IDS_IMPUTER_PATH", "imputer.pkl")
SCALER_PATH = os.environ.get("IDS_SCALER_PATH", "scaler.pkl")
COLUMNS_PATH = os.environ.get("IDS_COLUMNS_PATH", "feature_columns.json")

MONGO_URI = os.environ.get("IDS_MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = "ids_project"
MONGO_COLLECTION_NAME = "feedback_samples"

# SMTP — set these env vars to enable email alerts
SMTP_EMAIL     = os.environ.get("IDS_SMTP_EMAIL", "")
SMTP_PASSWORD  = os.environ.get("IDS_SMTP_PASSWORD", "")
SMTP_TO        = os.environ.get("IDS_SMTP_TO", "")
ALERT_THRESHOLD = float(os.environ.get("IDS_ALERT_THRESHOLD", "0.9"))

# ===== MongoDB =====
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client[MONGO_DB_NAME]
mongo_collection = mongo_db[MONGO_COLLECTION_NAME]

# ===== Load model =====
model = joblib.load(MODEL_PATH)
imputer = joblib.load(IMPUTER_PATH)
scaler = joblib.load(SCALER_PATH)

with open(COLUMNS_PATH) as f:
    feature_columns = json.load(f)

print("Model yüklendi:", MODEL_PATH)

# Multi-class model (optional — loads if file exists)
MULTICLASS_PATH = "xgboost_multiclass.pkl"
CATEGORY_NAMES_PATH = "category_names.json"
try:
    multiclass_model = joblib.load(MULTICLASS_PATH)
    with open(CATEGORY_NAMES_PATH) as f:
        category_names = json.load(f)
    print("Multiclass model yüklendi:", MULTICLASS_PATH)
except FileNotFoundError:
    multiclass_model = None
    category_names = {}


def _send_alert_email(result: dict, src_bytes, dst_bytes):
    """Fire-and-forget email alert (runs in background thread)."""
    if not all([SMTP_EMAIL, SMTP_PASSWORD, SMTP_TO]):
        return
    try:
        msg = MIMEMultipart()
        msg["Subject"] = "[IDS ALERT] Kritik Saldiri Tespit Edildi"
        msg["From"]    = SMTP_EMAIL
        msg["To"]      = SMTP_TO
        body = (
            f"Kritik saldir tespit edildi!\n\n"
            f"Tahmin         : {result['prediction']}\n"
            f"Saldir olasiligi: %{result['attack_probability'] * 100:.2f}\n"
            f"src_bytes      : {src_bytes}\n"
            f"dst_bytes      : {dst_bytes}\n"
            f"Zaman          : {datetime.now(timezone.utc).isoformat()}\n"
        )
        msg.attach(MIMEText(body, "plain", "utf-8"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, SMTP_TO, msg.as_string())
    except Exception as exc:
        print(f"[EMAIL] Gonderilemedi: {exc}")

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "AI-Based IDS API is running",
        "endpoints": ["/health", "/predict", "/feedback", "/feedback/list", "/retrain"]
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model": MODEL_PATH,
        "features": len(feature_columns),
        "smtp_configured": bool(SMTP_EMAIL and SMTP_PASSWORD and SMTP_TO),
        "alert_threshold": ALERT_THRESHOLD,
        "multiclass_available": multiclass_model is not None,
    })

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body"}), 400

        sample = pd.DataFrame([data])
        sample = sample.reindex(columns=feature_columns, fill_value=0)
        sample = sample.replace([np.inf, -np.inf], np.nan)
        sample_imp = imputer.transform(sample)
        sample_scaled = scaler.transform(sample_imp)

        pred = int(model.predict(sample_scaled)[0])
        proba = model.predict_proba(sample_scaled)[0]

        attack_category = "Normal"
        if multiclass_model is not None:
            cat_pred = int(multiclass_model.predict(sample_scaled)[0])
            attack_category = category_names.get(str(cat_pred), "Unknown")

        result = {
            "prediction": "ATTACK" if pred == 1 else "BENIGN",
            "predicted_label": pred,
            "benign_probability": float(proba[0]),
            "attack_probability": float(proba[1]),
            "attack_category": attack_category,
        }

        if pred == 1 and result["attack_probability"] >= ALERT_THRESHOLD:
            threading.Thread(
                target=_send_alert_email,
                args=(result, data.get("src_bytes", "?"), data.get("dst_bytes", "?")),
                daemon=True,
            ).start()

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/feedback", methods=["POST"])
def feedback():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body"}), 400

        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        mongo_collection.insert_one(data)

        return jsonify({
            "message": "Feedback saved to MongoDB",
            "mongo_db": MONGO_DB_NAME,
            "mongo_collection": MONGO_COLLECTION_NAME
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/feedback/list", methods=["GET"])
def feedback_list():
    try:
        limit = int(request.args.get("limit", 50))
        docs = list(
            mongo_collection.find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return jsonify({"count": len(docs), "samples": docs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/retrain", methods=["POST"])
def retrain_model():
    try:
        from retrain import retrain as run_retrain
        results = run_retrain()
        global model
        model = joblib.load(MODEL_PATH)
        return jsonify({"message": "Retraining tamamlandi", "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
