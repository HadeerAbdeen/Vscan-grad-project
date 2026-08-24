import pandas as pd
import numpy as np
import re
import joblib
import tldextract
import math
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ==========================================
# 1. نظام استخراج الخصائص الاحترافي (Advanced Feature Engineering) 🧠
# ==========================================
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    total_len = len(text)
    for x in range(256):
        p_x = float(text.count(chr(x))) / total_len
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(url):
    url = str(url).lower()
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
    except:
        domain = ""
        
    url_len = len(url)
    domain_len = len(domain) if domain else 1 # تجنب القسمة على صفر

    suspicious_keywords = ['login', 'verify', 'update', 'account', 'secure', 'banking', 'confirm', 'wallet', 'signin']
    
    # حسابات مساعدة
    digit_count = len(re.findall(r'\d', url))
    letter_count = len(re.findall(r'[a-z]', url))
    
    features = {
        # --- خصائص أساسية ---
        'url_length': url_len,
        'hostname_length': domain_len,
        'path_length': url_len - domain_len,
        
        # --- خصائص الرموز ---
        'dots': url.count('.'),
        'hyphens': url.count('-'),
        'at_symbol': url.count('@'),
        'question_mark': url.count('?'),
        'equals': url.count('='),
        'slashes': url.count('/'),
        'percent': url.count('%'),
        'underscore': url.count('_'),
        
        # --- خصائص متقدمة (الجديد) ---
        'entropy': calculate_entropy(url),
        'has_ip': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0,
        'is_https': 1 if 'https' in url else 0,
        'sus_keyword_count': sum(1 for w in suspicious_keywords if w in url),
        
        # --- نسب رياضية (Ratios) - دي بتفرق جداً في الدقة ---
        'digit_ratio': digit_count / url_len,        # نسبة الأرقام في الرابط
        'letter_ratio': letter_count / url_len,      # نسبة الحروف
        'symbol_ratio': (url_len - digit_count - letter_count) / url_len, # نسبة الرموز
        'domain_url_ratio': domain_len / url_len     # حجم الدومين بالنسبة للرابط كله
    }
    return features

# ==========================================
# 2. تحميل الداتا الكاملة (Full Dataset)
# ==========================================
csv_file = 'malicious_phish.csv'

if os.path.exists(csv_file):
    print(f"📊 Loading FULL Dataset from {csv_file}...")
    df = pd.read_csv(csv_file)
    
    # تنظيف
    df['binary_label'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)
    
    # ⚠️ هام: شيلنا الـ Sampling عشان نتدرب على الـ 650 ألف رابط كلهم
    print(f"🔥 Training on {len(df)} URLs (This is the real deal!)")
    
    print("⚙️ Extracting Advanced Features (Grab a coffee ☕)...")
    # استخدام apply بطريقة أسرع شوية
    features_df = df['url'].apply(lambda x: pd.Series(extract_features(x)))
    
    X = features_df
    y = df['binary_label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("🚀 Training Hyper-Tuned XGBoost Model...")
    # إعدادات الموديل "الوحش"
    model = XGBClassifier(
        n_estimators=500,      # رفعنا العدد لـ 500 شجرة (دقة أعلى)
        learning_rate=0.05,    # تعلم أبطأ بس أدق
        max_depth=12,          # عمق أكبر عشان يفهم العلاقات المعقدة
        subsample=0.8,         # بيستخدم 80% من الداتا في كل لفة عشان يمنع الحفظ (Overfitting)
        colsample_bytree=0.8,  # بيستخدم 80% من الخصائص
        eval_metric='logloss',
        use_label_encoder=False,
        n_jobs=-1              # استخدام كل قوة البروسيسور
    )
    
    model.fit(X_train, y_train)
    
    # تقييم
    print("\n🧪 Testing Model Accuracy...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"🏆 Final Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred))
    
    # حفظ
    print("💾 Saving the Beast to 'app/models/url_model.pkl'...")
    joblib.dump(model, 'app/models/url_model.pkl')
    print("✅ DONE!")

else:
    print("❌ Error: malicious_phish.csv not found!")