let backend_resource = await fetch("/api/message", {credentials: "include"}).then(r => r.status==200 ? r.text() : "Unauthorized")

document.getElementById("information").innerHTML = backend_resource

let user = await fetch("/auth/me", {credentials: "include"}).then(r => r.status==200 ? r.text() : "")

if (user.length > 0) {
    document.getElementById("status").innerHTML = "You are logged in as: " + user
    document.getElementById("login-ref").remove()
}
