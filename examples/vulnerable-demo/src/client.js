const params = new URLSearchParams(window.location.search);
const message = params.get("message") || "Welcome";

document.getElementById("message").innerHTML = message;
