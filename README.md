# 🛡️ AI Scam Detector

Paste a suspicious **message or URL** and get a scam-risk verdict (**Likely Scam / Suspicious / Low Risk**),
a risk score out of 100, the red flags found, and what to do next. Built with **Streamlit** and **Google Gemini Flash**.

## How it works
1. **Rule-based checks (no AI, instant):** looks for raw-IP links, look-alike (punycode) domains, `@` tricks,
   link shorteners, risky domain endings, brand impersonation (e.g. `paypal-secure-login.xyz`) and scam wording
   (urgency, OTP/password requests, prize claims, gift-card fees, threats...).
2. **Gemini analysis:** the text and the rule-based findings go to Gemini Flash, which returns a risk score,
   scam type, red flags and recommended actions.
3. **Combined verdict:** the AI score and the rule-based score are blended into the final result.

If Gemini is busy or no API key is set, the app still works using the rule-based checks only.

## Safety and privacy
- The app **never opens or fetches** pasted links. URLs are shown as plain text so you can't click them by accident.
- Pasted text is sent to Google Gemini for analysis. Don't paste passwords, OTPs or card numbers.
- Content you paste is treated as untrusted data, so a scam message can't instruct the AI to rate it "safe".
- No scam detector is 100% accurate. Use it as a second opinion, and verify through the company's official site or app.

## Run locally
```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free Gemini API key at https://aistudio.google.com/apikey, then provide it in one of these ways:

1. **Paste it in the app sidebar** (simplest), or
2. Set an environment variable: `export GEMINI_API_KEY="your-key"` (Windows: `set GEMINI_API_KEY=your-key`), or
3. Create `.streamlit/secrets.toml`:
   ```toml
   GEMINI_API_KEY = "your-key"
   ```

Start the app:
```bash
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Push this repo to GitHub (keep `app.py` and `requirements.txt` in the root).
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app** → choose your repo, branch `main`, main file `app.py`.
4. Open **Advanced settings → Secrets** and add: `GEMINI_API_KEY = "your-key"`
5. Click **Deploy**.

## Configuration
Edit the top of `app.py`:
- `MODEL_CHAIN` - Gemini models tried in order (retry, then fall back if one is overloaded)
- `BRANDS` - brands to protect against impersonation (add your bank or local services)
- `SUSPICIOUS_TLDS`, `MESSAGE_PATTERNS` - rule-based detection lists

## Project structure
```
app.py            # Streamlit app
requirements.txt  # Python dependencies
README.md
.gitignore
```
