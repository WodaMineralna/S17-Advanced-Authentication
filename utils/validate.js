const bcrypt = require("bcryptjs");

function isEmpty(arr) {
  const check = (val) => {
    return val.trim().length === 0;
  };

  // console.log(arr.length === 0 || arr.some(check)); // DEBUGGING
  return arr.length === 0 || arr.some(check);
}

function isMatching(str1, str2) {
  const rawStr1 = str1.trim();
  const rawStr2 = str2.trim();

  // console.log(rawStr1 === rawStr2) // DEBUGGING
  return rawStr1 === rawStr2;
}

async function comparePasswords(pwd1, pwd2) {
  return await bcrypt.compare(pwd1, pwd2);
}

module.exports = { isEmpty, isMatching, comparePasswords };
