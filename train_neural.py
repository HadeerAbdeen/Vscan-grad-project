import pandas as pd
import numpy as np
import os
import pickle
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout, Input
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

# ==========================================
# 1. تجهيز الداتا (Processing)
# ==========================================
csv_file = 'ultimate_dataset.csv'
if not os.path.exists(csv_file):
    print("❌ Error: malicious_phish.csv not found!")
    exit()

print("⏳ Loading Dataset (Deep Learning Mode)...")
df = pd.read_csv(csv_file)

# تحويل الرابط لنصوص (String)
urls = df['url'].values
labels = df['type'].apply(lambda x: 0 if x == 'benign' else 1).values

# ==========================================
# 2. التوكنايزر (تحويل الحروف لأرقام)
# ==========================================
print("⚙️ Tokenizing URLs (Teaching the AI to read)...")

# بنخلي الموديل يقرأ الرابط حرف حرف (Character Level)
tokenizer = Tokenizer(char_level=True, lower=True)
tokenizer.fit_on_texts(urls)

# تحويل الروابط لأرقام
sequences = tokenizer.texts_to_sequences(urls)
word_index = tokenizer.word_index
print(f"🔤 Found {len(word_index)} unique characters.")

# توحيد طول الروابط (عشان الشبكة العصبية تفهم)
# أي رابط أطول من 200 حرف هنقصه، وأقصر هنزوده أصفار
max_len = 200
data = pad_sequences(sequences, maxlen=max_len)

# تقسيم الداتا
X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.2, random_state=42)

# ==========================================
# 3. بناء المخ (Neural Network Architecture) 🧠
# ==========================================
print("🔥 Building the CNN Model...")

model = Sequential()
# طبقة الإدخال: بتحول الأرقام لمتجهات (Vectors)
model.add(Embedding(len(word_index) + 1, 32, input_length=max_len))

# طبقة الـ CNN: بتدور على أنماط خبيثة (زي g00gle, paypa1)
model.add(Conv1D(64, 5, activation='relu'))
model.add(GlobalMaxPooling1D())

# طبقات "التفكير" (Dense Layers)
model.add(Dense(64, activation='relu'))
model.add(Dropout(0.5)) # عشان يمنع الحفظ الصم (Overfitting)
model.add(Dense(1, activation='sigmoid')) # النتيجة (0 أو 1)

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# ==========================================
# 4. التدريب (Ignition) 🚀
# ==========================================
print("🏋️ Training Started (This might take time)...")

# وقف التدريب لو الدقة بطلت تزيد عشان منضيعش وقت
early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)

history = model.fit(
    X_train, y_train,
    epochs=10, # عدد الدورات
    batch_size=128,
    validation_data=(X_test, y_test),
    callbacks=[early_stop]
)

# ==========================================
# 5. الحفظ (Saving) 💾
# ==========================================
print("\n🧪 Evaluating Final Accuracy...")
loss, accuracy = model.evaluate(X_test, y_test)
print(f"🏆 Final Accuracy: {accuracy*100:.2f}%")

print("💾 Saving Model & Tokenizer...")
os.makedirs('app/models', exist_ok=True)

# لازم نحفظ حاجتين: الموديل + التوكنايزر (عشان نعرف نترجم الروابط بعدين)
model.save('app/models/url_model.h5') # صيغة Keras
with open('app/models/tokenizer.pickle', 'wb') as handle:
    pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

print("✅ DONE! The Neural Network is ready.")