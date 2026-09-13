document.addEventListener("DOMContentLoaded", function () {

    // ==============================
    // DASHBOARD - REAL GMAIL EMAILS
    // ==============================

    const emailList = document.getElementById("emailList");
    const emailCount = document.getElementById("emailCount");

    const emailSearch = document.getElementById("emailSearch");
const emailFilter = document.getElementById("emailFilter");

    if (emailList) {

        fetch("/gmail-emails")
            .then(function (response) {

                if (response.status === 401) {
                    window.location.href = "/";
                    return null;
                }

                return response.json();
            })

            .then(function (emails) {

                if (!emails) {
                    return;
                }

                emailList.innerHTML = "";

                if (emails.error) {
                    emailList.innerHTML =
                        "<p>Unable to load Gmail emails.</p>";
                    return;
                }

            if (emails.length === 0) {

    emailList.innerHTML =
        "<p>No emails found.</p>";

    if (emailCount) {
        emailCount.textContent = "0 messages";
    }

    return;
}

   if (emailCount) {
    emailCount.textContent =
        emails.length + " messages";
}
const currentUserEmail =
    document.querySelector(".user-email")?.textContent.trim();

if (currentUserEmail) {
    localStorage.setItem(
        "currentUserEmail",
        currentUserEmail
    );
}
const totalEmails =
    document.getElementById("totalEmails");

if (totalEmails) {
    totalEmails.textContent =
        emails.length;
}
const analyzedEmails =
    document.getElementById("analyzedEmails");

const safeEmails =
    document.getElementById("safeEmails");

const suspiciousEmails =
    document.getElementById("suspiciousEmails");

const phishingEmails =
    document.getElementById("phishingEmails");

const currentUserEmail =
    document.querySelector(".user-email")?.textContent.trim() || "guest";

const historyKey = "analysisHistory_" + currentUserEmail;

const analysisHistory =
    JSON.parse(
        localStorage.getItem(historyKey)
    ) || [];

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



let filteredEmails = emails;
let currentPage = 1;
const emailsPerPage = 15;

function displayEmails(page) {

    emailList.innerHTML = "";

    const start = (page - 1) * emailsPerPage;
    const end = start + emailsPerPage;

    const pageEmails =
        filteredEmails.slice(start, end);

    pageEmails.forEach(function (email) {

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
            function () {

                localStorage.setItem(
                    "selectedEmail",
                    JSON.stringify(email)
                );

                window.location.href = "/analysis";
            }
        );
    });

    const totalPages =
        Math.ceil(
            filteredEmails.length / emailsPerPage
        );

    const pagination =
        document.createElement("div");

    pagination.className = "pagination";

    if (totalPages > 1) {

        pagination.innerHTML = `
            <button id="prevBtn"
                ${page === 1 ? "disabled" : ""}>
                ← Previous
            </button>

            <span>
                Page ${page} of ${totalPages}
            </span>

            <button id="nextBtn"
                ${page === totalPages ? "disabled" : ""}>
                Next →
            </button>
        `;

        emailList.appendChild(pagination);

        document
            .getElementById("prevBtn")
            .addEventListener(
                "click",
                function () {

                    if (currentPage > 1) {
                        currentPage--;
                        displayEmails(currentPage);
                    }
                }
            );

        document
            .getElementById("nextBtn")
            .addEventListener(
                "click",
                function () {

                    if (currentPage < totalPages) {
                        currentPage++;
                        displayEmails(currentPage);
                    }
                }
            );
    }
}

if (emailSearch) {

    emailSearch.addEventListener(
        "input",
        function () {

            const searchText =
                emailSearch.value
                    .toLowerCase()
                    .trim();


            filteredEmails =
                emails.filter(
                    function (email) {

                        return (
                            (email.sender || "")
                                .toLowerCase()
                                .includes(searchText)

                            ||

                            (email.subject || "")
                                .toLowerCase()
                                .includes(searchText)

                            ||

                            (email.content || "")
                                .toLowerCase()
                                .includes(searchText)
                        );

                    }
                );


            currentPage = 1;

            displayEmails(
                currentPage
            );

        }
    );
}


displayEmails(currentPage);
})
            .catch(function (error) {

                console.error("Gmail error:", error);

                emailList.innerHTML =
                    "<p>Unable to load Gmail emails.</p>";
            });
    }


    // ==============================
    // ANALYSIS PAGE
    // ==============================

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

                fetch("/analyze-email", {

                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        content: selectedEmail.content || ""
                    })
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