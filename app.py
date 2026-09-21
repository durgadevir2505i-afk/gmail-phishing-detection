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

    
@app.route("/gmail-emails")
def gmail_emails():
    print("SESSION USER:", session.get("user"))
    print("SESSION KEYS:", list(session.keys()))

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
    page_token = request.args.get("page_token")
    search_query = request.args.get("q", "").strip()

    params = {
        "maxResults": 50
    }

    if search_query:
        params["q"] = search_query

    if page_token:
        params["pageToken"] = page_token

    response = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params=params,
        timeout=20
    )
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
            params=params,
            timeout=20
        )

    if response.status_code != 200:
        return jsonify({
            "error": "Unable to fetch Gmail messages",
            "details": response.text
        }), response.status_code

    response_data = response.json()

    messages = response_data.get("messages", [])
    next_page_token = response_data.get("nextPageToken")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def get_email(message):
        message_id = message["id"]

        try:
            detail_response = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
                headers=headers,
                params={
                    "format": "metadata",
                    "metadataHeaders": ["From", "Subject", "Date"]
                },
                timeout=10
            )

            if detail_response.status_code != 200:
                return None

            data = detail_response.json()

            sender = ""
            subject = ""
            date = ""

            for header in data.get("payload", {}).get("headers", []):
                name = header.get("name", "").lower()

                if name == "from":
                    sender = header.get("value", "")
                elif name == "subject":
                    subject = header.get("value", "")
                elif name == "date":
                    date = header.get("value", "")

            return {
                "id": message_id,
                "sender": sender,
                "subject": subject or "(No subject)",
                "date": date,
                "content": data.get("snippet", ""),
                "unread": "UNREAD" in data.get("labelIds", [])
            }

        except Exception:
            return None

    emails = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(get_email, message)
            for message in messages
        ]

        for future in as_completed(futures):
            result = future.result()

            if result:
                emails.append(result)
    print("EMAIL COUNT RETURNED:", len(emails))
    return jsonify({
        "emails": emails,
        "nextPageToken": next_page_token,
        "totalCount": response_data.get("resultSizeEstimate", 0)
    })
@app.route("/gmail-email/<message_id>")
def gmail_email(message_id):

    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    token = session.get("google_token")

    if not token or "access_token" not in token:
        return jsonify({"error": "Google token missing"}), 401

    access_token = token["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
        headers=headers,
        params={"format": "full"},
        timeout=20
    )

    if response.status_code != 200:
        return jsonify({
            "error": "Unable to fetch email",
            "details": response.text
        }), response.status_code

    data = response.json()

    sender = ""
    subject = ""
    date = ""

    for header in data.get("payload", {}).get("headers", []):
        name = header.get("name", "").lower()

        if name == "from":
            sender = header.get("value", "")
        elif name == "subject":
            subject = header.get("value", "")
        elif name == "date":
            date = header.get("value", "")

    import base64

    def extract_body(part):

        body_data = part.get("body", {}).get("data")

        if body_data:
            try:
                return base64.urlsafe_b64decode(
                    body_data + "=="
                ).decode(
                    "utf-8",
                    errors="ignore"
                )
            except Exception:
                return ""

        for child in part.get("parts", []):
            result = extract_body(child)

            if result:
                return result

        return ""

    content = extract_body(
        data.get("payload", {})
    )

    return jsonify({
        "id": message_id,
        "sender": sender,
        "subject": subject or "(No subject)",
        "date": date,
        "content": content or data.get("snippet", "")
    })

@app.route("/gmail-total")
def gmail_total():

    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    token = session.get("google_token")

    if not token or "access_token" not in token:
        return jsonify({"error": "Google token missing"}), 401

    access_token = token["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={
            "maxResults": 1
        },
        timeout=20
    )

    if response.status_code != 200:
        return jsonify({
            "error": "Unable to count Gmail messages",
            "details": response.text
        }), response.status_code

    data = response.json()

    total = data.get("resultSizeEstimate", 0)

    return jsonify({
        "totalCount": total
    })
@app.route("/gmail-total-exact")
def gmail_total_exact():

    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    token = session.get("google_token")

    if not token or "access_token" not in token:
        return jsonify({"error": "Google token missing"}), 401

    access_token = token["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    total_count = 0
    page_token = None

    try:

        while True:

            params = {
                "maxResults": 500
            }

            if page_token:
                params["pageToken"] = page_token

            response = requests.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code != 200:
                return jsonify({
                    "error": "Unable to count Gmail messages",
                    "details": response.text
                }), response.status_code

            data = response.json()

            total_count += len(
                data.get("messages", [])
            )

            page_token = data.get("nextPageToken")

            if not page_token:
                break

        return jsonify({
            "totalCount": total_count
        })

    except Exception as e:

        return jsonify({
            "error": "Exact Gmail count failed",
            "details": str(e)
        }), 500




@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        user=session["user"]
    )
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

    print("DEBUG SESSION:", dict(session))

    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    message_id = data.get("message_id")

    if not message_id:
        return jsonify({"error": "Message ID is missing"}), 400

    # -----------------------------
    # Get Full Gmail Email
    # -----------------------------

    google_token = session.get("google_token", {})

    access_token = google_token.get("access_token")
    refresh_token = google_token.get("refresh_token")
    if not access_token:
        return jsonify({"error": "Gmail access token missing"}), 401

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    gmail_url = (
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
        "?format=full"
    )

    response = requests.get(gmail_url, headers=headers)

    # Refresh token if access token expired
    if response.status_code == 401 and refresh_token:

        try:
            token_response = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token"
                }
            )

            new_token = token_response.json().get("access_token")

            if new_token:
                session["access_token"] = new_token

                headers = {
                    "Authorization": f"Bearer {new_token}"
                }

                response = requests.get(
                    gmail_url,
                    headers=headers
                )

        except Exception:
            pass

    if response.status_code != 200:
        return jsonify({
            "error": "Unable to fetch email from Gmail"
        }), response.status_code

    message_data = response.json()

    # -----------------------------
    # Extract Email Text
    # -----------------------------

    def extract_text(payload):

        text_parts = []

        if payload.get("mimeType") == "text/plain":
            body = payload.get("body", {})
            data = body.get("data")

            if data:
                try:
                    decoded = base64.urlsafe_b64decode(
                        data + "=="
                    ).decode("utf-8", errors="ignore")

                    text_parts.append(decoded)
                except Exception:
                    pass

        for part in payload.get("parts", []):

            text_parts.extend(
                extract_text(part)
            )

        return text_parts

    email_text_parts = extract_text(
        message_data.get("payload", {})
    )

    email_content = "\n".join(
        email_text_parts
    )

    # If body is empty, use Gmail snippet
    if not email_content.strip():
        email_content = message_data.get(
            "snippet",
            ""
        )

    # -----------------------------
    # Get Subject and Sender
    # -----------------------------

    subject = ""
    sender = ""

    headers_data = message_data.get(
        "payload", {}
    ).get("headers", [])

    for header in headers_data:

        name = header.get("name", "").lower()

        if name == "subject":
            subject = header.get("value", "")

        elif name == "from":
            sender = header.get("value", "")

    # Include subject and sender in ML analysis
    analysis_text = (
        "Subject: " + subject +
        "\nFrom: " + sender +
        "\n" + email_content
    )

    print("ANALYSIS TEXT LENGTH:", len(analysis_text))

    if not analysis_text.strip():
        return jsonify({
            "error": "Email content is empty"
        }), 400

    # -----------------------------
    # Machine Learning Prediction
    # -----------------------------

    email_vector = vectorizer.transform(
        [analysis_text]
    )

    probabilities = model.predict_proba(
        email_vector
    )[0]

    phishing_probability = probabilities[1]

    ml_risk_score = phishing_probability * 100

    # -----------------------------
    # Phishing Indicators
    # -----------------------------

    text = analysis_text.lower()

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
                "Suspicious indicator detected: "
                + word
            )

            indicator_score += score

    # -----------------------------
    # URL Detection
    # -----------------------------

    if "http://" in text or "https://" in text:

        indicators.append(
            "Email contains a link."
        )

        indicator_score += 8

    # -----------------------------
    # Sensitive Information Detection
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
                "Sensitive information request detected: "
                + word
            )

            indicator_score += 12

    # Limit indicator score to 100
    indicator_score = min(
        100,
        indicator_score
    )

    # -----------------------------
    # Combine ML + Indicators
    # -----------------------------

    risk_score = (
        (ml_risk_score * 0.70)
        +
        (indicator_score * 0.30)
    )

    risk_score = min(
        100,
        max(0, risk_score)
    )

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
    # Model Confidence
    # -----------------------------

    confidence = max(
        probabilities
    ) * 100

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

