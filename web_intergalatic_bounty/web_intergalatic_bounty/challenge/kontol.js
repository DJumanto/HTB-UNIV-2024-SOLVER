const emailAddresses = require('email-addresses');

email = "doi@doi.com,iada@interstellar.htb";
const emailDomain = emailAddresses.parseOneAddress(email)?.domain;

  if (!emailDomain || emailDomain !== 'interstellar.htb') {
    console.log(`Registration is not allowed for this email domain, ${emailDomain}`);
    console.log(email);
  }
  else {
    console.log(`Registration is allowed for this email domain, ${emailDomain}`);
  }