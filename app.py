import os
from flask import Flask, redirect, url_for, session, render_template, request, jsonify
import joblib
import requests

model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="")

app.secret_key = "my-super-secret-key-12345"

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
       "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"
    },
)


@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))

    return render_template("index.html")


@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(
    redirect_uri,
    access_type="offline",
    prompt="consent"
)

@app.route("/authorize")
def authorize():
    print("AUTHORIZE ROUTE REACHED")
    token = google.authorize_access_token()
    user_info = token.get("userinfo")

    session["user"] = {
        "name": user_info.get("name"),
        "email": user_info.get("email"),
        "picture": user_info.get("picture"),
    }

    session["google_token"] = {
        "access_token": token.get("access_token"),
        "refresh_token": token.get("refresh_token")
    }
    print("TOKEN RECEIVED:", bool(token.get("access_token")))
    print("REFRESH TOKEN RECEIVED:", bool(token.get("refresh_token")))

    return redirect(url_for("dashboard"))

    


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        user=session["user"]
    )
@app.route("/gmail-emails")
def gmail_emails():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    token = session.get("google_token")

    if not token or "access_token" not in token:
        return jsonify({"error": "Google token missing"}), 401

    access_token = token["access_token"]
    refresh_token = token.get("refresh_token")

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    # Get Gmail message list
    response = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"maxResults": 500},
        timeout=30
    )

    # Refresh expired access token
    if response.status_code == 401 and refresh_token:
        refresh_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            },
            timeout=15
        )

        if refresh_response.status_code != 200:
            return jsonify({
                "error": "Google token expired. Please login again."
            }), 401

        new_token = refresh_response.json()
        access_token = new_token["access_token"]

        session["google_token"]["access_token"] = access_token
        session.modified = True

        headers["Authorization"] = f"Bearer {access_token}"

        response = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers=headers,
            params={"maxResults": 500},
            timeout=30
        )

    if response.status_code != 200:
        return jsonify({
            "error": "Unable to fetch Gmail messages",
            "details": response.text
        }), response.status_code

    response_data = response.json()
    messages = response_data.get("messages", [])

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def get_email(message):
        message_id = message["id"]

        try:
            detail_response = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
                headers=headers,
                params={
                    "format": "metadata",
                    "metadataHeaders": ["From", "Subject"]
                },
                timeout=15
            )

            if detail_response.status_code != 200:
                return None

            data = detail_response.json()

            sender = ""
            subject = ""

            for header in data.get("payload", {}).get("headers", []):
                name = header.get("name", "").lower()

                if name == "from":
                    sender = header.get("value", "")

                elif name == "subject":
                    subject = header.get("value", "")

            labels = data.get("labelIds", [])

            return {
                "id": message_id,
                "sender": sender,
                "subject": subject,
                "content": data.get("snippet", ""),
                "unread": "UNREAD" in labels
            }

        except Exception:
            return None

    emails = []

    # Fetch email details in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = [
            executor.submit(get_email, message)
            for message in messages
        ]

        for future in as_completed(futures):
            result = future.result()

            if result:
                emails.append(result)

    return jsonify(emails)

    


@app.route("/analysis")
def analysis():

    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "analysis.html",
        user=session["user"]
    )


@app.route("/result")
def result():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "result.html",
        user=session["user"]
    )
@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    email_content = data.get("content", "")

    if not email_content.strip():
        return jsonify({"error": "Email content is empty"}), 400

    # -----------------------------
    # Machine Learning Prediction
    # -----------------------------

    email_vector = vectorizer.transform([email_content])

    probabilities = model.predict_proba(email_vector)[0]

    phishing_probability = probabilities[1]
    ml_risk_score = phishing_probability * 100

    # -----------------------------
    # Phishing Indicators
    # -----------------------------

    text = email_content.lower()
    indicators = []
    indicator_score = 0

    suspicious_words = {
        "urgent": 8,
        "immediately": 8,
        "verify": 8,
        "suspended": 10,
        "password": 8,
        "click here": 10,
        "confirm": 6,
        "account": 4,
        "security alert": 10,
        "unusual activity": 10,
        "limited time": 8,
        "act now": 10,
        "winner": 10,
        "prize": 10,
        "claim": 6,
        "bank": 5,
        "payment": 4
    }

    for word, score in suspicious_words.items():
        if word in text:
            indicators.append(
                "Suspicious indicator detected: " + word
            )
            indicator_score += score

    # -----------------------------
    # URL Detection
    # -----------------------------

    if "http://" in text or "https://" in text:
        indicators.append("Email contains a link.")
        indicator_score += 8

    # -----------------------------
    # Personal Information Request
    # -----------------------------

    personal_info_words = [
        "otp",
        "credit card",
        "card number",
        "cvv",
        "pin",
        "username",
        "login details",
        "personal information"
    ]

    for word in personal_info_words:
        if word in text:
            indicators.append(
                "Sensitive information request detected: " + word
            )
            indicator_score += 12

    # -----------------------------
    # Combine ML + Indicators
    # -----------------------------

    risk_score = (ml_risk_score * 0.70) + (indicator_score * 0.30)

    risk_score = min(100, max(0, risk_score))

    # -----------------------------
    # Final Classification
    # -----------------------------

    if risk_score >= 70:
        verdict = "Phishing"
        risk_level = "High"

    elif risk_score >= 40:
        verdict = "Suspicious"
        risk_level = "Medium"

    else:
        verdict = "Safe"
        risk_level = "Low"

    # -----------------------------
    # Confidence
    # -----------------------------

    confidence = max(probabilities) * 100

    if not indicators:
        indicators.append(
            "No major phishing indicators detected."
        )

    return jsonify({
        "verdict": verdict,
        "riskLevel": risk_level,
        "riskScore": round(risk_score),
        "confidence": round(confidence),
        "indicators": indicators
    })
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=False)

