document.addEventListener("DOMContentLoaded", function () {

// ==============================
// DASHBOARD - REAL GMAIL EMAILS
// ==============================

const emailList = document.getElementById("emailList");
const emailCount = document.getElementById("emailCount");
const emailSearch = document.getElementById("emailSearch");


let currentGmailPage = 1;
let totalGmailEstimate = 0;

let totalCountLoading = false;
let totalCountLoaded = false;

let gmailPageToken = "";
let gmailNextPageToken = null;
let gmailPreviousTokens = [];
let gmailSearchQuery = "";
let totalGmailCount = 0;
function loadGmailEmails(pageToken = "") {

    if (!emailList) return;

    emailList.innerHTML = "<p>Loading emails...</p>";

    fetch(
    "/gmail-emails?page_token=" +
    encodeURIComponent(pageToken) +
    "&q=" +
    encodeURIComponent(gmailSearchQuery)
)
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {

            if (data.error) {
                emailList.innerHTML = "<p>Unable to load Gmail emails.</p>";
                return;
            }

            const emails = data.emails || [];
            if (gmailSearchQuery) {
totalGmailEstimate = data.totalCount || emails.length;
}

            gmailNextPageToken = data.nextPageToken || null;

displayEmails(emails);

if (emailCount) {
    emailCount.textContent =
        "Page " + currentGmailPage +
        " • " + emails.length + " messages";
}

const totalEmails =
    document.getElementById("totalEmails");

if (totalEmails) {
    totalEmails.textContent =
        totalGmailEstimate;
}


// ANALYSIS COUNTS
const currentUserEmail =
    document.querySelector(".user-email")?.textContent.trim() || "guest";

localStorage.setItem(
    "currentUserEmail",
    currentUserEmail
);

const historyKey =
    "analysisHistory_" + currentUserEmail;

const analysisHistory =
    JSON.parse(
        localStorage.getItem(historyKey)
    ) || [];

const analyzedEmails =
    document.getElementById("analyzedEmails");

const safeEmails =
    document.getElementById("safeEmails");

const suspiciousEmails =
    document.getElementById("suspiciousEmails");

const phishingEmails =
    document.getElementById("phishingEmails");

if (analyzedEmails) {
    analyzedEmails.textContent =
        analysisHistory.length;
}

if (safeEmails) {
    safeEmails.textContent =
        analysisHistory.filter(
            item => item.verdict === "Safe"
        ).length;
}

if (suspiciousEmails) {
    suspiciousEmails.textContent =
        analysisHistory.filter(
            item => item.verdict === "Suspicious"
        ).length;
}

if (phishingEmails) {
    phishingEmails.textContent =
        analysisHistory.filter(
            item => item.verdict === "Phishing"
        ).length;
}
        })
        .catch(function(error) {

            console.error("Gmail error:", error);

            emailList.innerHTML =
                "<p>Unable to load Gmail emails.</p>";
        });
}if (emailSearch) {
    emailSearch.addEventListener("input", function () {
        gmailSearchQuery = emailSearch.value.trim();

        gmailPageToken = "";
        gmailNextPageToken = null;
        gmailPreviousTokens = [];
        currentGmailPage = 1;

        loadGmailEmails();
    });
}
function loadExactTotalCount() {

    if (totalCountLoading || totalCountLoaded) {
        return;
    }

    totalCountLoading = true;

    const totalEmails =
        document.getElementById("totalEmails");

    if (totalEmails) {
        totalEmails.textContent = "Counting...";
    }

    fetch("/gmail-total-exact")
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {

            if (data.error) {
                console.error(
                    "Total count error:",
                    data.error
                );
                return;
            }

            totalGmailEstimate =
                data.totalCount || 0;

            totalCountLoaded = true;

            if (totalEmails) {
                totalEmails.textContent =
                    totalGmailEstimate;
            }
        })
        .catch(function(error) {

            console.error(
                "Exact total count error:",
                error
            );
        })
        .finally(function() {

            totalCountLoading = false;
        });
}
function displayEmails(emails) {

    emailList.innerHTML = "";

    emails.forEach(function(email) {

        const row = document.createElement("div");

        row.className = "email-row";

        row.innerHTML = `
            <div class="email-row-main">

                <div class="email-sender">
                    ${email.sender || "Unknown sender"}
                </div>

                <div class="email-subject">
                    ${email.subject || "(No subject)"}
                </div>

                <div class="email-preview">
                    ${email.content || ""}
                </div>

            </div>

            <button class="btn-primary">
                Analyze
            </button>
        `;

        emailList.appendChild(row);

        row.querySelector("button").addEventListener(
            "click",
            function() {

                localStorage.setItem(
                    "selectedEmail",
                    JSON.stringify(email)
                );

                window.location.href = "/analysis";
            }
        );
    });


    // PAGINATION
    const pagination = document.createElement("div");

    pagination.className = "pagination";

    const totalPages =
        Math.ceil(totalGmailEstimate / 50)

    pagination.innerHTML = `
        <button id="prevGmailBtn"
            ${currentGmailPage === 1 ? "disabled" : ""}>
            ← Previous
        </button>

        <span>
            Page ${currentGmailPage} of ${totalPages}
        </span>

        <button id="nextGmailBtn"
            ${!gmailNextPageToken ? "disabled" : ""}>
            Next →
        </button>
    `;

    emailList.appendChild(pagination);


    // NEXT
    document
        .getElementById("nextGmailBtn")
        .addEventListener(
            "click",
            function() {

                if (!gmailNextPageToken) return;

                gmailPreviousTokens.push(
                    gmailPageToken
                );

                gmailPageToken =
                    gmailNextPageToken;

                currentGmailPage++;

                loadGmailEmails(
                    gmailPageToken
                );
            }
        );


    // PREVIOUS
    document
        .getElementById("prevGmailBtn")
        .addEventListener(
            "click",
            function() {

                if (currentGmailPage === 1) return;

                gmailPageToken =
                    gmailPreviousTokens.pop() || "";

                currentGmailPage--;

                loadGmailEmails(
                    gmailPageToken
                );
            }
        );
}


// LOAD FIRST PAGE
if (emailList) {
    loadGmailEmails();
    loadExactTotalCount();
}
    const selectedEmailData =
        localStorage.getItem("selectedEmail");

    if (selectedEmailData) {

        const selectedEmail =
            JSON.parse(selectedEmailData);

        const detailSpans =
            document.querySelectorAll(
                ".email-details .detail-row span"
            );

        const contentBox =
            document.querySelector(".content-box");

        if (detailSpans.length >= 2) {

            detailSpans[0].textContent =
                selectedEmail.sender;

            detailSpans[1].textContent =
                selectedEmail.subject;
        }

        if (contentBox) {

            const paragraphs =
                contentBox.querySelectorAll("p");

            if (paragraphs.length > 0) {

                paragraphs[0].textContent =
                    selectedEmail.content;
            }

            for (let i = 1; i < paragraphs.length; i++) {
                paragraphs[i].remove();
            }
        }
    }


    // ==============================
    // ANALYZE BUTTON
    // ==============================

    const analyzeBtn =
        document.getElementById("analyzeBtn");

    if (analyzeBtn) {

        analyzeBtn.addEventListener(
            "click",
            function () {

                const selectedEmail =
                    JSON.parse(
                        localStorage.getItem("selectedEmail")
                    );

                if (!selectedEmail) {
                    alert("Please select an email first.");
                    return;
                }

                analyzeBtn.disabled = true;
                analyzeBtn.textContent = "Analyzing...";

                const note =
                    document.getElementById("analyzingNote");

                if (note) {
                    note.hidden = false;
                }

fetch("/gmail-email/" + encodeURIComponent(selectedEmail.id))
    .then(function(response) {
        return response.json();
    })
    .then(function(fullEmail) {

        if (fullEmail.error) {
            throw new Error(fullEmail.error);
        }

        return fetch("/analyze-email", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
    message_id: selectedEmail.id
})
        });
    })
                .then(function (response) {
                    return response.json();
                })

                .then(function (result) {

                    if (result.error) {
                        throw new Error(result.error);
                    }

                    localStorage.setItem(
                    "analysisResult",
                     JSON.stringify(result)
                     );
const currentUserEmail =
    localStorage.getItem("currentUserEmail") || "guest";

const historyKey = "analysisHistory_" + currentUserEmail;

const history =
    JSON.parse(
        localStorage.getItem(historyKey)
    ) || [];

history.push(result);

localStorage.setItem(
    historyKey,
    JSON.stringify(history)
);
                    window.location.href = "/result";
                })

                .catch(function (error) {

                    console.error(
                        "Analysis error:",
                        error
                    );

                    alert(
                        "Unable to analyze the email."
                    );

                    analyzeBtn.disabled = false;
                    analyzeBtn.textContent = "Analyze Email";

                    if (note) {
                        note.hidden = true;
                    }
                });
            }
        );
    }


    // ==============================
    // RESULT PAGE
    // ==============================

    const resultData =
        localStorage.getItem("analysisResult");

    if (resultData) {

        const result =
            JSON.parse(resultData);

        const statusLabel =
            document.getElementById("statusLabel");

        const statusSub =
            document.getElementById("statusSub");

        const riskValue =
            document.getElementById("riskValue");

        const confidenceValue =
            document.getElementById("confidenceValue");

        const riskBar =
            document.getElementById("riskBar");

        const indicatorsList =
            document.getElementById("indicatorsList");

        const statusIcon =
            document.getElementById("statusIcon");


        if (statusLabel) {

            if (result.verdict === "Phishing") {

                statusLabel.textContent =
                    "⚠️ Phishing Detected";

            } else if (result.verdict === "Suspicious") {

                statusLabel.textContent =
                    "⚠️ Suspicious Email";

            } else {

                statusLabel.textContent =
                    "✅ Safe Email";
            }
        }


        if (statusSub) {

            statusSub.textContent =
                "The email has been analyzed successfully.";
        }


        if (riskValue) {

            riskValue.textContent =
                result.riskLevel +
                " (" +
                result.riskScore +
                "/100)";
        }


        if (confidenceValue) {

            confidenceValue.textContent =
                result.confidence + "%";
        }


        if (riskBar) {

            riskBar.style.width =
                result.riskScore + "%";
        }


        if (statusIcon) {

            statusIcon.textContent =
                result.verdict === "Safe"
                    ? "✓"
                    : "!";
        }


        if (indicatorsList) {

            indicatorsList.innerHTML = "";

            if (
                result.indicators &&
                result.indicators.length > 0
            ) {

                result.indicators.forEach(
                    function (indicator) {

                        const li =
                            document.createElement("li");

                        li.textContent = indicator;

                        indicatorsList.appendChild(li);
                    }
                );

            } else {

                const li =
                    document.createElement("li");

                li.textContent =
                    "No major phishing indicators detected.";

                indicatorsList.appendChild(li);
            }
        }
    }

});