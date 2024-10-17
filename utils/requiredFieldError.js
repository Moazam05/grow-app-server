function checkRequiredFields(data, requiredFields) {
  return requiredFields.filter((field) => !data[field]);
}

module.exports = checkRequiredFields;
