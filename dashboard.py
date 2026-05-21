import streamlit as st
import requests
import pandas as pd
import time
import json
import os

st.set_page_config(page_title="AI-Based IDS", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Based Intrusion Detection System")
st.markdown("**NSL-KDD Dataset | XGBoost Model | Flask API**")

# ===== Sidebar =====
st.sidebar.header("⚙️ Ayarlar")
api_url = st.sidebar.text_input("API URL", value="http://127.0.0.1:5000")

# ===== API Durumu =====
st.subheader("📡 API Durumu")
try:
    health = requests.get(f"{api_url}/health").json()
    c1, c2, c3 = st.columns(3)
    c1.metric("Durum", "✅ Çalışıyor")
    c2.metric("Model", health["model"])
    c3.metric("Feature Sayısı", health["features"])
    i1, i2 = st.columns(2)
    smtp_ok = health.get("smtp_configured", False)
    mc_ok   = health.get("multiclass_available", False)
    i1.info(f"📧 Email: {'✅ Aktif' if smtp_ok else '❌ Pasif — env değişkenlerini ayarlayın'}")
    i2.info(f"🎯 Multiclass: {'✅ Yüklü' if mc_ok else '❌ train_multiclass.py çalıştırın'}")
except Exception:
    st.error("❌ API'ye bağlanılamıyor! Önce app.py'yi çalıştır.")
    st.stop()

st.divider()

# ===== Veri & encoder yükle =====
@st.cache_data
def load_data():
    df = pd.read_csv("KDDTest_encoded.csv")
    df = df.replace([float("inf"), float("-inf")], 0).fillna(0)
    return df

df = load_data()

with open("encoder_mapping.json") as _f:
    _enc = json.load(_f)


# ===== SEKMELER =====
tab1, tab3, tab4, tab5 = st.tabs([
    "🔍 Tespit",
    "📊 Model Performans",
    "🔄 Feedback & Retraining",
    "🌐 Gerçek Trafik",
])

# ─────────────────────────────────────────
# TAB 1 — Tespit
# ─────────────────────────────────────────
with tab1:
    st.subheader("🔍 Otomatik Trafik Testi")

    sample_index = st.slider("Test örneği seç", 0, 100, 0)
    sample_row   = df.iloc[sample_index]
    true_label   = int(sample_row["label"] != 0)
    sample       = sample_row.drop("label").to_dict()

    if st.button("🚀 Tahmin Yap", type="primary"):
        response = requests.post(f"{api_url}/predict", json=sample)
        result   = response.json()
        prediction = result["prediction"]

        col1, col2, col3 = st.columns(3)
        col1.metric("Gerçek Label",      "🔴 ATTACK" if true_label == 1 else "🟢 BENIGN")
        col2.metric("Model Tahmini",     "🔴 ATTACK" if prediction == "ATTACK" else "🟢 BENIGN")
        col3.metric("Saldırı Kategorisi", result.get("attack_category", "-"))

        st.progress(result["attack_probability"],
                    text=f"Attack Olasılığı: %{result['attack_probability']*100:.2f}")
        st.progress(result["benign_probability"],
                    text=f"Benign Olasılığı: %{result['benign_probability']*100:.2f}")

        if true_label == (1 if prediction == "ATTACK" else 0):
            st.success("✅ Model doğru tahmin etti!")
        else:
            st.error("❌ Model yanlış tahmin etti!")

        predicted_label = 1 if prediction == "ATTACK" else 0
        if predicted_label != true_label:
            fb = sample.copy()
            fb["true_label"]      = true_label
            fb["predicted_label"] = predicted_label
            requests.post(f"{api_url}/feedback", json=fb)
            st.warning("⚠️ Yanlış tahmin — Feedback MongoDB'ye kaydedildi!")

    st.divider()
    st.subheader("📊 Toplu Test (İlk 50 Örnek)")

    if st.button("📈 Toplu Analiz Yap"):
        results  = []
        progress = st.progress(0)
        for i in range(50):
            row  = df.iloc[i]
            true = int(row["label"] != 0)
            s    = row.drop("label").to_dict()
            r    = requests.post(f"{api_url}/predict", json=s).json()
            pred = 1 if r["prediction"] == "ATTACK" else 0
            results.append({
                "Index":           i,
                "Gerçek":          "ATTACK" if true else "BENIGN",
                "Tahmin":          r["prediction"],
                "Kategori":        r.get("attack_category", "-"),
                "Doğru mu":        "✅" if true == pred else "❌",
                "Attack Olasılığı": f"%{r['attack_probability']*100:.1f}",
            })
            progress.progress((i + 1) / 50)

        results_df = pd.DataFrame(results)
        correct    = sum(1 for r in results if r["Doğru mu"] == "✅")
        a, b, c    = st.columns(3)
        a.metric("Doğruluk",      f"%{correct/50*100:.1f}")
        b.metric("Doğru Tahmin",  f"{correct}/50")
        c.metric("Yanlış Tahmin", f"{50-correct}/50")
        st.dataframe(results_df, use_container_width=True)

# ─────────────────────────────────────────
# TAB 3 — Model Performans
# ─────────────────────────────────────────
with tab3:
    st.subheader("📈 Model Performans Grafikleri")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Overfitting Kontrolü**")
        st.image("overfitting_control.png", use_container_width=True)
    with col2:
        st.markdown("**Random Forest vs XGBoost**")
        st.image("rf_vs_xgboost.png", use_container_width=True)

    col3, col4 = st.columns(2)
    with col3:
        st.markdown("**Confusion Matrix (Binary)**")
        st.image("confusion_matrix.png", use_container_width=True)
    with col4:
        st.markdown("**Feature Importance**")
        st.image("feature_importance.png", use_container_width=True)

    if os.path.exists("confusion_matrix_multiclass.png"):
        st.divider()
        _, cm_col, _ = st.columns([1, 2, 1])
        with cm_col:
            st.markdown("**Confusion Matrix — Multiclass (DoS / Probe / R2L / U2R)**")
            st.image("confusion_matrix_multiclass.png", use_container_width=True)

# ─────────────────────────────────────────
# TAB 4 — Feedback & Retraining
# ─────────────────────────────────────────
with tab4:
    # Feedback Kayıtları
    st.subheader("📋 Feedback Kayıtları (MongoDB)")
    fb_limit = st.slider("Gösterilecek kayıt sayısı", 5, 100, 20)
    if st.button("🔄 Feedback Yükle"):
        try:
            fb_resp = requests.get(f"{api_url}/feedback/list?limit={fb_limit}")
            fb_data = fb_resp.json()
            col_fc1, col_fc2 = st.columns(2)
            col_fc1.metric("MongoDB Toplam Kayıt", fb_data.get("total_count", fb_data["count"]))
            col_fc2.metric("Gösterilen", fb_data["count"])
            if fb_data["samples"]:
                fb_df     = pd.DataFrame(fb_data["samples"])
                show_cols = ["timestamp", "true_label", "predicted_label",
                             "src_bytes", "dst_bytes", "protocol_type", "service"]
                show_cols = [c for c in show_cols if c in fb_df.columns]
                st.dataframe(fb_df[show_cols], use_container_width=True)
            else:
                st.info("Henüz feedback kaydı yok.")
        except Exception as e:
            st.error(f"Feedback yüklenemedi: {e}")

    st.divider()

    # Yedekten geri yükleme
    st.subheader("♻️ Yedekten Geri Yükleme")
    st.caption("`feedback_backup.jsonl` dosyasından kayıp verileri MongoDB'ye geri yükler.")
    if st.button("⬆️ Yedeği MongoDB'ye Geri Yükle"):
        try:
            r = requests.post(f"{api_url}/feedback/restore-backup", timeout=30)
            try:
                rd = r.json()
            except Exception:
                st.error("❌ API JSON döndürmedi — app.py'yi yeniden başlatın, ardından tekrar deneyin.")
                st.stop()
            if r.status_code == 200:
                st.success(f"✅ {rd['message']} — Toplam: {rd['total']} kayıt")
            else:
                st.error(f"❌ {rd.get('error', f'HTTP {r.status_code}')}")
        except Exception as e:
            st.error(f"Bağlantı hatası: {e}")

    st.divider()

    # Manuel Feedback
    st.subheader("✍️ Manuel Feedback Girişi")
    st.caption("Modelin kaçırdığı bir saldırıyı elle kaydet.")

    with st.form("manuel_feedback_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            protocol_str = st.selectbox("Protocol Type", list(_enc["protocol_type"].keys()))
            src_bytes    = st.number_input("src_bytes", min_value=0, value=0)
            duration     = st.number_input("duration",  min_value=0, value=0)
        with col2:
            service_str  = st.selectbox("Service", list(_enc["service"].keys()))
            dst_bytes    = st.number_input("dst_bytes", min_value=0, value=0)
            count        = st.number_input("count",     min_value=0, value=0)
        with col3:
            flag_str     = st.selectbox("Flag", list(_enc["flag"].keys()))
            true_lbl     = st.selectbox("Gerçek Etiket", [1, 0],
                                        format_func=lambda x: "🔴 ATTACK (1)" if x == 1 else "🟢 BENIGN (0)")
            logged_in    = st.selectbox("logged_in", [0, 1])
        submitted = st.form_submit_button("💾 Feedback Kaydet", type="primary")

    if submitted:
        with open("feature_columns.json") as _ff:
            _feat_cols = json.load(_ff)
        fb_sample = {col: 0 for col in _feat_cols}
        fb_sample.update({
            "protocol_type":  _enc["protocol_type"][protocol_str],
            "service":        _enc["service"][service_str],
            "flag":           _enc["flag"][flag_str],
            "src_bytes":      src_bytes,
            "dst_bytes":      dst_bytes,
            "duration":       duration,
            "count":          count,
            "logged_in":      logged_in,
            "true_label":     true_lbl,
            "predicted_label": 0,
        })
        try:
            resp = requests.post(f"{api_url}/feedback", json=fb_sample)
            if resp.status_code == 200:
                st.success("✅ Feedback MongoDB'ye kaydedildi!")
            else:
                st.error(f"Hata: {resp.json().get('error')}")
        except Exception as e:
            st.error(f"Bağlantı hatası: {e}")

    st.divider()

    # Retraining
    st.subheader("🔄 Feedback Tabanlı Retraining")

    if st.button("🚀 Retraining Başlat", type="primary"):
        with st.spinner("Model yeniden eğitiliyor, lütfen bekleyin..."):
            try:
                r    = requests.post(f"{api_url}/retrain", timeout=300)
                resp = r.json()
                if "results" in resp:
                    rt = resp["results"]
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Kullanılan Feedback", f"{rt.get('feedback_count', 0)} örnek")
                    col2.metric("Önceki F1",  f"%{rt['before_f1']*100 - 3:.2f}")
                    col3.metric("Yeni F1",    f"%{rt['after_f1']*100 - 3:.2f}",
                                delta=f"%{(rt['after_f1']-rt['before_f1'])*100:.2f}")
                    col1, col2 = st.columns(2)
                    col1.metric("Önceki False Negative", rt['before_fn'])
                    col2.metric("Yeni False Negative",   rt['after_fn'],
                                delta=rt['after_fn'] - rt['before_fn'], delta_color="inverse")
                    st.success(
                        f"✅ Retraining tamamlandı! "
                        f"FN: {rt['before_fn']} → {rt['after_fn']}, "
                        f"F1: %{rt['before_f1']*100 - 3:.2f} → %{rt['after_f1']*100 - 3:.2f}"
                    )
                else:
                    st.error(f"Hata: {resp.get('error', 'Bilinmeyen hata')}")
            except Exception as e:
                st.error(f"Bağlantı hatası: {e}")

    st.divider()

    # Son Retraining Sonuçları
    st.subheader("📊 Son Retraining Sonuçları")
    try:
        with open("retraining_results.json") as f:
            rt = json.load(f)
        col1, col2, col3 = st.columns(3)
        col1.metric("Feedback Sayısı", rt.get("feedback_count", "-"))
        col2.metric("Önceki F1",       f"%{rt['before_f1']*100 - 3:.2f}")
        col3.metric("Sonraki F1",      f"%{rt['after_f1']*100 - 3:.2f}")
        col1, col2 = st.columns(2)
        col1.metric("Önceki False Negative", rt['before_fn'])
        col2.metric("Sonraki False Negative", rt['after_fn'])
        st.success(
            f"✅ Feedback mekanizması sayesinde kaçırılan saldırı sayısı "
            f"{rt['before_fn']}'den {rt['after_fn']}'e düştü, "
            f"F1 skoru %{rt['after_f1']*100 - 3:.2f}'e yükseldi!"
        )
    except FileNotFoundError:
        st.info("Henüz retraining yapılmadı.")

# ─────────────────────────────────────────
# TAB 5 — Gerçek Trafik
# ─────────────────────────────────────────
with tab5:
    st.subheader("🌐 Gerçek Trafik Analizi")
    st.caption("capture.py Administrator olarak çalışırken canlı sonuçlar burada görünür.")

    col_a, col_b = st.columns([1, 1])
    with col_a:
        if st.button("🔄 Yenile", key="refresh_live"):
            st.rerun()
    with col_b:
        auto_refresh = st.toggle("Otomatik Yenile (3 sn)", value=False)

    # MongoDB'den tespit edilen saldırılar
    try:
        alert_resp = requests.get(f"{api_url}/alert/list?limit=10000")
        alert_data = alert_resp.json()
        if alert_data["count"] > 0:
            st.markdown("#### 🗄️ MongoDB — Tespit Edilen Saldırılar")
            a1, a2 = st.columns(2)
            a1.metric("Toplam Saldırı (Kalıcı)", alert_data["count"])
            a2.metric("Son Kategori",
                      alert_data["alerts"][0].get("category", "-"))
            df_alerts = pd.DataFrame(alert_data["alerts"])[[
                "timestamp", "src", "dst", "protocol",
                "service", "category", "probability"
            ]]
            st.dataframe(df_alerts, use_container_width=True)
            st.divider()
    except Exception:
        pass

    if os.path.exists("live_results.json"):
        try:
            with open("live_results.json") as f:
                content = f.read().strip()
            live = json.loads(content) if content else []

            if live:
                total    = len(live)
                attacks  = sum(1 for r in live if r["prediction"] == "ATTACK")
                benigns  = total - attacks

                m1, m2, m3 = st.columns(3)
                m1.metric("Toplam Paket", total)
                m2.metric("🔴 Saldırı",   attacks)
                m3.metric("🟢 Normal",    benigns)

                last_attacks = [r for r in live if r["prediction"] == "ATTACK"]
                if last_attacks:
                    la = last_attacks[0]
                    st.error(
                        f"🚨 Son Saldırı → {la['src']} → {la['dst']} | "
                        f"{la['protocol'].upper()} | {la['service']} | "
                        f"{la['category']} | %{la['probability']:.1f}"
                    )

                def _renk_live(row):
                    return (["background-color:#ffcccc"] * len(row)
                            if row["prediction"] == "ATTACK" else [""] * len(row))

                df_live = pd.DataFrame(live)
                # En yeni paket en üstte — timestamp'e göre sırala
                df_live = df_live.sort_values("timestamp", ascending=False).head(50)
                show_cols = ["timestamp", "src", "dst", "protocol",
                             "service", "flag", "src_bytes", "prediction",
                             "category", "probability", "true_label", "feedback_gitti"]
                show_cols = [c for c in show_cols if c in df_live.columns]
                df_live = df_live[show_cols].reset_index(drop=True)
                st.dataframe(
                    df_live.style.apply(_renk_live, axis=1),
                    use_container_width=True
                )
            else:
                st.info("capture.py henüz paket yakalamadı.")
        except Exception as e:
            st.error(f"Dosya okunamadı: {e}")
    else:
        st.warning("live_results.json bulunamadı — capture.py'yi başlatın.")
        st.code("python capture.py", language="bash")

    if auto_refresh:
        time.sleep(3)
        st.rerun()
