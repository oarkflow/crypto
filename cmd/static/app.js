// Function to switch between tabs
function openTab(evt, tabName) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablink");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

// Function to submit a form via POST (JSON) to the specified endpoint
function submitForm(formId, endpoint) {
    var form = document.getElementById(formId);
    var formData = new FormData(form);
    var object = {};
    formData.forEach((value, key) => {
        object[key] = value;
    });
    var json = JSON.stringify(object);
    fetch(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: json
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById("response").innerText = JSON.stringify(data, null, 2);
        })
        .catch(error => {
            document.getElementById("response").innerText = "Error: " + error;
        });
}

// Open the first tab by default when the page loads
document.addEventListener("DOMContentLoaded", function () {
    var defaultTab = document.getElementsByClassName("tablink")[0];
    if (defaultTab) {
        defaultTab.click();
    }
});
