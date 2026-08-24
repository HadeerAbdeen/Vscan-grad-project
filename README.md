# 🛡️ VScan - AI-Powered Security System

![Project Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**VScan** is an advanced, cyberpunk-themed security tool designed to detect malicious URLs and files using Artificial Intelligence and heuristic analysis. It features a robust user authentication system and a personalized dashboard for tracking scan history.

---

## 🚀 Features (Current State)

### ✅ Completed & Working:
- **🔐 Secure Authentication:**
  - Full Login/Register system with JWT (JSON Web Tokens).
  - Password hashing using Bcrypt.
  - Session management (Auto-logout & Protected Routes).

- **🌐 URL Scanner Engine:**
  - Detects Phishing and Malicious links.
  - Real-time analysis with risk scoring.

- **📊 User Dashboard:**
  - **Profile Page:** Displays user details and scan history.
  - **Visual Analytics:** Interactive Chart.js doughnut chart showing Safe vs. Malicious scans.
  - **Scan History:** Persistent database storage for every user's activity.

- **🎨 Cyberpunk UI/UX:**
  - Neon-themed interface.
  - Responsive design (Mobile & Desktop).
  - Floating particles and glassmorphism effects.

---

## 🛠️ Tech Stack

- **Backend:** Python (FastAPI), SQLAlchemy, SQLite, Pydantic.
- **Frontend:** HTML5, CSS3 (Custom Cyberpunk Theme), JavaScript (Vanilla).
- **Security:** OAuth2, JWT, Passlib (Bcrypt).
- **Visualization:** Chart.js.

---

## 🔮 Roadmap (What's Next?)

- [ ] **📁 File Scanner:** Implement AI-based file analysis (PE headers, Malware detection).
- [ ] **📄 Report Export:** Generate professional PDF reports for scan results.
- [ ] **🔊 Sound Effects:** Add sci-fi SFX for interactions (Scan complete, Alarm).
- [ ] **🤖 Smart Chatbot:** Enhance the AI assistant for security advice.
- [ ] **🌍 Deployment:** Host the application online.

---

## ⚙️ How to Run Locally

Follow these steps to set up the project on your machine:

### 1. Clone the repository
```bash
git clone [https://github.com/Mohamed-Hegazy0/VScan-Security-System.git](https://github.com/Mohamed-Hegazy0/VScan-Security-System.git)
cd VScan-Security-System
2. Create & Activate Virtual Environment
It's recommended to use a virtual environment to manage dependencies.

Bash

python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate
3. Install Dependencies
Bash

pip install -r requirements.txt
4. Run the Server
Start the FastAPI server with live reloading:

Bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --env-file .env  #امر التشغيل لاستقبال اي traffic خارجيه
#only to run permethus & gravana
sudo docker-compose up -d

5. Access the App
Open your browser and navigate to: http://127.0.0.1:8000
# VScan-Security-System
# VScan-Security-System
