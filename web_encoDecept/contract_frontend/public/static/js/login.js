const auth = (atype) => {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  if (email.trim() == "" || password.trim() == "") {
    showMessage("All fields required!")
  }

  fetch(`/api/${atype}`, {
    headers: {
      'Content-Type': 'application/json'
    },
    method: 'POST',
    body: JSON.stringify({email: email, password: password})
  })
  .then((res) => {return res.json()})
  .then((data) => {
    showMessage(data.message)
  })
};

const showMessage = (message) => {
  document.getElementById("message").innerHTML = message;

  setTimeout(() => {
    document.getElementById("message").innerHTML = "";
  }, 5000);
};

let lbtn = document.getElementById("loginBtn");
let rbtn = document.getElementById("registerBtn");

if (rbtn !== null) {
  rbtn.addEventListener("click", () => auth("register"));
}

if (lbtn !== null) {
  lbtn.addEventListener("click", () => auth("login"));
}
