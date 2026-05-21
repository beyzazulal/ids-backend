# AI-Based Intrusion Detection System (IDS)

Yapay zeka tabanlı ağ saldırısı tespit sistemi. NSL-KDD veri seti üzerinde eğitilmiş XGBoost modeli kullanılarak gerçek zamanlı ağ trafiğini analiz eder ve saldırıları tespit eder.

## Mimari

```
capture.py  →  app.py (Flask API)  →  dashboard.py (Streamlit)
   (Ağ dinleme)     (Tahmin & MongoDB)      (Görselleştirme)
```

## Özellikler

- Gerçek zamanlı ağ trafiği yakalama ve analiz
- Binary sınıflandırma: ATTACK / BENIGN
- Multiclass sınıflandırma: DoS / Probe / R2L / U2R
- Feedback tabanlı otomatik model retraining
- MongoDB ile kalıcı veri saklama
- E-posta alarmı (SMTP)
- Saldırı simülatörü (SYN Flood, ICMP Flood, UDP Flood, Port Scan)

## Teknolojiler

| Katman | Teknoloji |
|---|---|
| Model | XGBoost |
| API | Flask |
| Veritabanı | MongoDB |
| Dashboard | Streamlit |
| Paket Yakalama | Scapy + Npcap |
| Veri Seti | NSL-KDD |

## Dosya Yapısı

```
ids-backend/
├── app.py                      # Flask API — tahmin, feedback, retraining
├── dashboard.py                # Streamlit dashboard
├── capture.py                  # Gerçek trafik yakalama
├── attack_sim.py               # Saldırı simülatörü
├── retrain.py                  # Feedback tabanlı retraining
├── train_multiclass.py         # Multiclass model eğitimi
├── xgboost_ids_final.pkl       # Binary sınıflandırma modeli
├── xgboost_multiclass.pkl      # Multiclass sınıflandırma modeli
├── imputer.pkl                 # Eksik değer doldurucu
├── scaler.pkl                  # Normalizasyon
├── feature_columns.json        # Model feature listesi
├── encoder_mapping.json        # Kategorik encoding tablosu
├── category_names.json         # Saldırı kategori isimleri
├── KDDTrain+.txt               # Eğitim veri seti
├── KDDTest+.txt                # Test veri seti
└── KDDTest_encoded.csv         # Encode edilmiş test verisi
```

## Kurulum

### Gereksinimler

```bash
pip install flask pymongo xgboost scikit-learn pandas numpy scapy requests streamlit joblib
```

Windows'ta paket yakalama için [Npcap](https://npcap.com/) kurulumu gereklidir.

### Çalıştırma

**1. Flask API'yi başlat:**
```bash
python app.py
```

**2. Dashboard'u başlat:**
```bash
streamlit run dashboard.py
```

**3. Gerçek trafik yakalamayı başlat (Administrator olarak):**
```bash
python capture.py
```

**4. Saldırı simülatörünü çalıştır (ayrı bilgisayarda, Administrator olarak):**
```bash
python attack_sim.py
```

## API Endpoint'leri

| Endpoint | Method | Açıklama |
|---|---|---|
| `/` | GET | API durum bilgisi |
| `/health` | GET | Model ve servis durumu |
| `/predict` | POST | Trafik tahmini (ATTACK/BENIGN) |
| `/feedback` | POST | Yanlış tahmin bildirimi |
| `/feedback/list` | GET | MongoDB feedback kayıtları |
| `/retrain` | POST | Modeli yeniden eğit |

## Model Bilgisi

- **Algoritma:** XGBoost (Binary + Multiclass)
- **Veri Seti:** NSL-KDD
- **En önemli feature'lar:** `src_bytes`, `flag`, `dst_bytes`, `count`, `protocol_type`
- **Preprocessing:** Label Encoding (protocol_type, service, flag) → Imputer → StandardScaler

## Saldırı Tipleri

| Tip | Açıklama |
|---|---|
| SYN Flood | Hedef porta kitlesel SYN paketi |
| ICMP Flood | Ping flood (DoS) |
| UDP Flood | UDP portu taşırma |
| Port Scan | Açık port keşfi |

## Feedback & Retraining Döngüsü

```
Yanlış tahmin tespit edilir
       ↓
MongoDB'ye kaydedilir (feedback_samples)
       ↓
/retrain endpoint'i çağrılır
       ↓
KDDTrain + Feedback verisiyle model yeniden eğitilir
       ↓
Yeni model F1 skoru karşılaştırılır ve kaydedilir
```

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `IDS_MODEL_PATH` | `xgboost_ids_final.pkl` | Model dosya yolu |
| `IDS_MONGO_URI` | `mongodb://localhost:27017/` | MongoDB bağlantısı |
| `IDS_SMTP_EMAIL` | — | Alarm e-posta adresi |
| `IDS_SMTP_PASSWORD` | — | E-posta şifresi |
| `IDS_SMTP_TO` | — | Alarm gönderilecek adres |
| `IDS_ALERT_THRESHOLD` | `0.9` | Alarm eşiği (%90) |
