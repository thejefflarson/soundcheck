// Prototype pollution — intentionally vulnerable. DO NOT deploy.

// BUG: recursive merge without key filtering
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]); // recurses into __proto__
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// BUG: Object.assign with parsed user input
function updateConfig(config, userInput) {
  return Object.assign(config, JSON.parse(userInput));
  // userInput: '{"__proto__":{"isAdmin":true}}'
}

// BUG: dynamic property set from user-controlled key
function setProperty(obj, key, value) {
  obj[key] = value; // key = "__proto__" pollutes all objects
}

// Usage — an attacker sends {"__proto__": {"isAdmin": true}}
const config = {};
deepMerge(config, JSON.parse('{"__proto__":{"isAdmin":true}}'));
console.log({}.isAdmin); // true — all objects are now "admin"
