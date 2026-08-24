import pandas as pd
import numpy as np
import joblib
import tldextract
import math
import re
import requests
import io
from urllib.parse import urlparse
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# =========================================================
# 1. إعدادات التدريب الضخم
# =========================================================
# هل تريد تحميل أحدث قائمة فيروسات من الإنترنت؟
DOWNLOAD_MALICIOUS_DATA = True 
# مسار القائمة البيضاء (المليون موقع)
WHITELIST_PATH = 'data/top_1m.csv' 
# مسار الموديل الجديد
MODEL_OUTPUT_PATH = 'app/models/url_model.pkl'

print("🚀 Starting Massive Training Pipeline...")

# =========================================================
# 2. دوال استخراج الخصائص (نفس المحرك الحالي)
# =========================================================
def calc_entropy(string):
    if not string: return 0
    entropy = 0
    for x in range(256):
        p_x = float(string.count(chr(x)))/len(string)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(url):
    features = []
    url = str(url)
    try:
        ext = tldextract.extract(url)
        domain = ext.domain
        subdomain = ext.subdomain
        suffix = ext.suffix
        hostname = f"{subdomain}.{domain}.{suffix}" if subdomain else f"{domain}.{suffix}"
        path = urlparse(url).path
    except:
        domain, subdomain, suffix, hostname, path = "", "", "", "", ""

    features.append(len(url))
    features.append(len(hostname))
    features.append(len(path))
    features.append(len(subdomain))
    features.append(len(domain))
    features.append(calc_entropy(url))
    features.append(calc_entropy(domain))
    chars = ['.', '-', '@', '?', '%', '=', '_', '&', '~']
    for char in chars: features.append(url.count(char))
    features.append(url.count('http'))
    features.append(url.count('https'))
    features.append(url.count('www'))
    total_len = len(url)
    digits_len = sum(c.isdigit() for c in url)
    features.append(digits_len / total_len if total_len > 0 else 0)
    sus_tlds = ['xyz', 'top', 'club', 'info', 'tk', 'cn', 'ga', 'cf', 'gq', 'ml', 'site', 'online']
    features.append(1 if suffix in sus_tlds else 0)
    features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0)
    features.append(1 if len(url) < 20 else 0)
    suspicious_words = ['login', 'signin', 'verify', 'update', 'bank', 'secure', 'account', 'confirm', 'paypal', 'apple', 'google', 'wallet', 'crypto', 'binance']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
    features.append(1 if '.php' in url or '.exe' in url or '.sh' in url else 0)
    features.append(subdomain.count('.'))
    
    return features

# =========================================================
# 3. تجميع البيانات (Data Gathering)
# =========================================================

# أ) تحميل الداتا الخبيثة (Malicious)
if DOWNLOAD_MALICIOUS_DATA:
    print("🌍 Downloading fresh malicious URLs from URLHaus (Please wait)...")
    try:
        # بنحمل داتا حقيقية من موقع URLHaus (محدثة يومياً)
        url = "https://urlhaus.abuse.ch/downloads/csv_online/"
        s = requests.get(url).content
        # تخطي التعليقات في الملف (أول 9 سطور عادة)
        malicious_df = pd.read_csv(io.StringIO(s.decode('utf-8')), skiprows=9)
        # اسم العمود اللي فيه الرابط هو 'url'
        malicious_urls = malicious_df['url'].tolist()
        print(f"😈 Loaded {len(malicious_urls)} REAL malicious URLs.")
    except Exception as e:
        print(f"❌ Failed to download: {e}")
        print("⚠️ Using dummy malicious data instead.")
        malicious_urls = ['http://bad-site.xyz/login', 'http://fake-bank.com'] * 500
else:
    # لو عندك ملف جاهز ممكن تحمله هنا
    pass

# ب) تحميل الداتا السليمة (Whitelist)
print("📂 Loading Top 1M Whitelist...")
try:
    with open(WHITELIST_PATH, 'r') as f:
        # بنحمل أول 200,000 موقع بس عشان الذاكرة (ممكن تزود لو جهازك قوي)
        # أو ناخد عدد مساوي لعدد المواقع الخبيثة عشان التوازن
        limit = len(malicious_urls) * 2 # هناخد ضعف عدد الخبيث عشان الأمان أهم
        safe_urls = [line.strip() for line in f][:limit]
        
    # إضافة المواقع المصرية المهمة يدوياً للتأكيد
    safe_urls.extend([
        "tanta.edu.eg", "cu.edu.eg", "egypt.gov.eg", "yallakora.com", 
        "youm7.com", "ahram.org.eg", "moe.gov.eg"
    ])
    print(f"😇 Loaded {len(safe_urls)} Safe URLs (Balanced).")
except Exception as e:
    print(f"❌ Error loading whitelist: {e}")
    safe_urls = ['google.com', 'facebook.com'] * 500

# =========================================================
# 4. التجهيز والتدريب (Processing & Training)
# =========================================================

# دمج البيانات
print("🔄 Merging datasets...")
df_malicious = pd.DataFrame({'url': malicious_urls, 'label': 1})
df_safe = pd.DataFrame({'url': safe_urls, 'label': 0})
df_final = pd.concat([df_malicious, df_safe], ignore_index=True)

# خلط البيانات (Shuffle)
df_final = df_final.sample(frac=1).reset_index(drop=True)

print(f"📊 Final Dataset Size: {len(df_final)} URLs")

# استخراج الخصائص (دي أطول خطوة)
print("⚙️ Extracting features (This may take a few minutes)...")
X = []
y = []

# بنعمل Loop بس بنحاول نعالج الأخطاء لو فيه رابط بايظ
for index, row in df_final.iterrows():
    try:
        feats = extract_features(row['url'])
        X.append(feats)
        y.append(row['label'])
    except:
        pass

X = np.array(X)
y = np.array(y)

# التقسيم
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# التدريب
print("🚀 Training XGBoost Model on Massive Data...")
model = XGBClassifier(
    n_estimators=100,      # عدد الأشجار
    learning_rate=0.1,     # سرعة التعلم
    max_depth=6,           # عمق الشجرة
    use_label_encoder=False, 
    eval_metric='logloss'
)
model.fit(X_train, y_train)

# التقييم
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print("-" * 30)
print(f"🏆 Model Accuracy: {acc * 100:.2f}%")
print("-" * 30)
print("Detailed Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))

# الحفظ
joblib.dump(model, MODEL_OUTPUT_PATH)
print(f"💾 SUPER MODEL saved to '{MODEL_OUTPUT_PATH}'")
print("✅ Restart your server to use the new brain!")