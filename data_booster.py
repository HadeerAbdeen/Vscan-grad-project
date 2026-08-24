import pandas as pd
import requests
import zipfile
import io
import os

def boost_dataset():
    print("🚀 Starting Data Booster...")

    # 1. تحميل قائمة Tranco (أشهر مواقع في العالم)
    print("📥 Downloading Top Safe Sites (Tranco List)...")
    try:
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip")
        z = zipfile.ZipFile(io.BytesIO(r.content))
        # استخراج الملف وقراءته
        with z.open(z.namelist()[0]) as f:
            tranco_df = pd.read_csv(f, header=None, names=['rank', 'url'])
    except Exception as e:
        print(f"❌ Failed to download Tranco list: {e}")
        return

    # هناخد أهم 30,000 موقع بس (عشان التدريب ميبقاش تقيل جداً)
    # ده كافي جداً إنه يعلمه يعني إيه موقع "مشهور وآمن"
    top_safe_sites = tranco_df.head(100000)['url'].tolist()
    
    print(f"✅ Loaded {len(top_safe_sites)} top safe domains.")

    # 2. تجهيز البيانات الآمنة
    # الموديل محتاج يشوف الرابط بـ http و https عشان يفهم
    safe_urls = []
    for domain in top_safe_sites:
        safe_urls.append(f"http://{domain}")
        safe_urls.append(f"https://{domain}")
        safe_urls.append(f"https://www.{domain}")
    
    # تحويلهم لـ DataFrame بنفس شكل الداتا القديمة
    new_safe_df = pd.DataFrame({
        'url': safe_urls,
        'type': ['benign'] * len(safe_urls) # تصنيفهم كلهم "آمن"
    })

    print(f"🧬 Generated {len(new_safe_df)} variations of safe URLs.")

    # 3. دمج مع الداتا القديمة
    old_csv = 'malicious_phish.csv'
    if os.path.exists(old_csv):
        print("📂 Loading existing dataset...")
        old_df = pd.read_csv(old_csv)
        
        # الدمج
        print("🔄 Merging datasets...")
        combined_df = pd.concat([old_df, new_safe_df], ignore_index=True)
        
        # خلط البيانات (Shuffle) عشان الموديل ميبقاش حافظ الترتيب
        combined_df = combined_df.sample(frac=1).reset_index(drop=True)
        
        # الحفظ
        output_file = 'ultimate_dataset.csv'
        combined_df.to_csv(output_file, index=False)
        print(f"🎉 SUCCESS! New super dataset saved as '{output_file}'")
        print(f"📊 Total URLs: {len(combined_df)}")
        
    else:
        print(f"❌ Error: {old_csv} not found. Please put it in the same folder.")

if __name__ == "__main__":
    boost_dataset()