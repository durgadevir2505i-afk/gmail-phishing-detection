from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib


# =========================================================
# TRAINING DATA
# 1 = Phishing
# 0 = Safe
# =========================================================

phishing_emails = [

    # Account / Security
    "Your account has been suspended. Verify your account immediately.",
    "Security alert. Your account will be closed unless you verify your identity.",
    "We detected unusual activity on your account. Confirm your details now.",
    "Your account requires immediate verification.",
    "Your account access has been temporarily restricted. Verify now.",
    "Someone tried to access your account. Confirm your identity immediately.",
    "Your security information has expired. Update it now.",
    "Failure to verify your account will result in permanent suspension.",
    "Your account will be disabled today. Click the link to restore access.",
    "Important security notification. Verify your account immediately.",

    # Password
    "Your password has expired. Click here to reset your password.",
    "Reset your password immediately to avoid account suspension.",
    "We received a request to change your password. Confirm now.",
    "Your password needs verification. Click the link below.",
    "Your password will expire today. Update it immediately.",
    "Someone requested a password reset. Verify your account now.",
    "Confirm your password to continue using your account.",
    "Your login credentials need to be verified immediately.",

    # Banking / Financial
    "Your bank account requires immediate verification.",
    "Your bank account has been temporarily blocked. Verify your details.",
    "Confirm your banking information to avoid account suspension.",
    "Your online banking account needs verification immediately.",
    "Unusual transaction detected. Click here to verify your bank account.",
    "Your payment account has been suspended. Confirm your identity.",
    "Verify your bank details to prevent your account from being closed.",
    "Your financial account requires urgent security verification.",
    "We detected a suspicious transaction. Confirm your account now.",
    "Your banking profile needs immediate verification.",

    # Payment
    "Your payment could not be processed. Click here to confirm your information.",
    "A payment is waiting for confirmation. Verify your account now.",
    "Your payment has been placed on hold. Confirm your details.",
    "Your transaction requires immediate verification.",
    "Click here to confirm your recent payment.",
    "Your payment account has been restricted. Verify your information.",

    # Prize / Reward
    "Congratulations! You have won a prize. Click here to claim your reward.",
    "You have been selected for a special reward. Claim it now.",
    "You are the lucky winner. Confirm your details to receive your prize.",
    "Your reward is waiting. Click the link to claim it.",
    "Congratulations! You have received a cash reward. Verify your information.",
    "You have won a special gift. Provide your details to receive it.",

    # Urgent messages
    "URGENT! Your account needs immediate verification.",
    "Important! Click the link immediately to prevent account suspension.",
    "Act now or your account will be permanently closed.",
    "Immediate action required. Verify your information now.",
    "You must confirm your account within 24 hours.",
    "Your account will be deleted unless you verify immediately.",
    "Urgent security notice. Click here to confirm your identity.",

    # Delivery / Shopping scams
    "Your package could not be delivered. Confirm your address using the link.",
    "Your delivery is on hold. Click here to update your payment information.",
    "Your parcel requires address verification immediately.",
    "Delivery failed. Confirm your details to reschedule your package.",
    "Your shipment is waiting for payment confirmation.",

    # Fake login
    "Your login session has expired. Sign in again using the link below.",
    "Confirm your login information to continue.",
    "Your account login requires verification.",
    "Click here to verify your login credentials.",
    "We need to confirm your username and password.",

    # General phishing
    "Click the link below and enter your personal information.",
    "Verify your identity by submitting your account details.",
    "Please confirm your personal information immediately.",
    "Your information needs to be updated urgently.",
    "Failure to provide the requested information will result in account closure."
]


safe_emails = [

    # Personal
    "Hi, how are you? Let me know when you are free.",
    "Good morning. Hope you are doing well.",
    "It was nice talking to you yesterday.",
    "Can we meet this weekend?",
    "Thank you for your message.",
    "Please call me when you are available.",
    "Hope you have a wonderful day.",
    "Happy birthday! Have a great day.",
    "Let's plan a meeting for next week.",
    "I will send the documents tomorrow.",

    # College / Education
    "The college timetable has been attached for your reference.",
    "The project meeting is scheduled for tomorrow at 10 AM.",
    "Please find the assignment attached.",
    "The internal examination will be conducted next Monday.",
    "Students are requested to attend the seminar.",
    "The department meeting will begin at 2 PM.",
    "Please submit your project report before Friday.",
    "The college has announced the examination schedule.",
    "Your attendance report is available for review.",
    "The workshop will be held in the computer science department.",

    # Work
    "Thank you for attending the meeting. Here are the notes.",
    "Please find the monthly report attached.",
    "The project deadline has been moved to next week.",
    "Please review the document and share your feedback.",
    "The team meeting is scheduled for Monday.",
    "I have attached the presentation for tomorrow's meeting.",
    "Please complete the assigned task by Friday.",
    "Here are the minutes from today's meeting.",
    "The updated project file is attached.",
    "Thank you for your contribution to the project.",

    # Shopping / Orders
    "Your order has been confirmed and will be delivered tomorrow.",
    "Thank you for your purchase. Your order is being processed.",
    "Your package has been shipped successfully.",
    "Your order has been delivered.",
    "Your shopping receipt is attached.",
    "Your monthly subscription has been renewed successfully.",
    "Your order history is available in your account.",
    "Thank you for shopping with us.",

    # Payments / Receipts
    "Your payment receipt is available in your account.",
    "Your payment was successfully completed.",
    "Thank you for your payment.",
    "Your invoice is attached for your records.",
    "The transaction was completed successfully.",
    "Your subscription payment has been received.",

    # Notifications
    "Your appointment is scheduled for tomorrow at 11 AM.",
    "This is a reminder about your upcoming appointment.",
    "Your registration has been completed successfully.",
    "Your application has been received.",
    "Your feedback has been recorded.",
    "The requested document is ready for download.",

    # Newsletters / Information
    "Here is this week's newsletter.",
    "Thank you for subscribing to our newsletter.",
    "Here are the latest updates from our organization.",
    "The monthly newsletter is attached.",
    "We hope you enjoy this month's updates.",

    # Professional
    "Please review the attached document at your convenience.",
    "I have shared the files for your reference.",
    "Let me know if you need any additional information.",
    "Thank you for your cooperation.",
    "Please contact me if you have any questions.",
    "I will provide the requested information shortly."
]


# =========================================================
# COMBINE DATA
# =========================================================

emails = phishing_emails + safe_emails

labels = (
    [1] * len(phishing_emails)
    + [0] * len(safe_emails)
)


print("======================================")
print("AI PHISHING DETECTION MODEL TRAINING")
print("======================================")

print("Total emails:", len(emails))
print("Phishing emails:", len(phishing_emails))
print("Safe emails:", len(safe_emails))


# =========================================================
# TF-IDF
# =========================================================

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    sublinear_tf=True
)

X = vectorizer.fit_transform(emails)


# =========================================================
# TRAIN / TEST SPLIT
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    labels,
    test_size=0.20,
    random_state=42,
    stratify=labels
)


# =========================================================
# MACHINE LEARNING MODEL
# =========================================================

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train, y_train)


# =========================================================
# MODEL EVALUATION
# =========================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print()
print("Model Accuracy:", round(accuracy * 100, 2), "%")
print()
print("Classification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Safe", "Phishing"],
    zero_division=0
))


# =========================================================
# SAVE MODEL
# =========================================================

joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")


print("======================================")
print("ML MODEL TRAINED SUCCESSFULLY!")
print("======================================")
print("Created:")
print("phishing_model.pkl")
print("tfidf_vectorizer.pkl")