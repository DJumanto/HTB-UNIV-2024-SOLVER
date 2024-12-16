const show_message = (msg) => {
  $(".message").css("display", "block");
  $(".message").text(msg);

  setTimeout(() => {
    $(".message").css("display", "none");
  }, 5000);
};

const showOtpModal = (email) => {
  $("#otpModal #email").text(email);

  $("#otpModal").modal("show");
};

const verifyOtp = () => {
  let otp = $("#otp").val();
  let email = $("#email").val();


  if ($.trim(otp) === "") {
    $('#modalMessage').text("OTP cannot be empty.");
    return;
  }

  fetch("/api/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: email,
      code: otp,
    }),
  })
    .then((res) => res.json())
    .then((data) => {
      if (data.status == 200) {
        show_message("Account verified successfully! Please login again.");
        $("#otpModal").modal("hide");
      } else {
        $('#modalMessage').text(data.message || "Invalid OTP. Please try again.");
      }
    })
    .catch((err) => {
      console.error("Error during OTP verification:", err);
      $('#modalMessage').text("An error occurred during OTP verification. Please try again.");
    });
};


const login = () => {
  let email = $("#email").val();
  let password = $("#password").val();

  if ($.trim(email) === "" || $.trim(password) === "") {
    show_message("Email and password cannot be empty.");
    return;
  }

  fetch("/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: email,
      password: password,
    }),
  })
    .then((res) => res.json())
    .then((data) => {
      if (data.status == 200) {
        let date = new Date();
        date.setTime(date.getTime() + 1 * 24 * 60 * 60 * 1000);
        let expires = "expires=" + date.toUTCString();
        document.cookie = "auth=" + data.token + "; " + expires + "; path=/";

        window.location.replace("/home");
      } else if (data.status == 403 && data.message === "Account not verified") {
        fetch('/api/sendEmail', {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email: email,
          })
        })
        .then(() => {
          showOtpModal(email);
        })
      } else {
        show_message("Invalid Credentials");
      }
    })
    .catch((err) => {
      console.error("Error during login:", err);
      show_message("An error occurred during login. Please try again.");
    });
};

const register = () => {
  let email = $("#email").val();
  let password = $("#password").val();

  if ($.trim(email) === "" || $.trim(password) === "") {
    show_message();
    return;
  }

  fetch("/api/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: email,
      password: password,
    }),
  })
    .then((res) => {
      return res.json();
    })
    .then((data) => {
      if (data.status == 201) {
        show_message("User Registered! Please login.");
        return;
      }
      else if(data.message == "Registration is not allowed for this email domain") {
        return show_message("Registration is not allowed for this email domain");
      }
      else {
        return show_message("email already exists!");
      }
    });
};
