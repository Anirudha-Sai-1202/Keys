// Test the transformation logic
const sampleKey = {
  "keyNumber": "1",
  "keyName": ["A001"],
  "location": "Ground Floor - Block A",
  "description": "class Room",
  "category": "classroom",
  "department": "class",
  "frequentlyUsed": false
};

const keyName = Array.isArray(sampleKey.keyName) ? sampleKey.keyName.join('/') : sampleKey.keyName;
const location = sampleKey.location.replace(/\s+/g, '_').replace(/-/g, '_');

const transformed = {
  ...sampleKey,
  keyNumber: `${keyName}_${location}`,
  keyName: keyName,
};

console.log('Original keyNumber:', sampleKey.keyNumber);
console.log('Transformed keyNumber:', transformed.keyNumber);
console.log('Transformed keyName:', transformed.keyName);
