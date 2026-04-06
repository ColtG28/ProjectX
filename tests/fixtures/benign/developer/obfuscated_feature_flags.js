const flags = ["ZXhwZXJpbWVudA==", "bGlnaHQ="];
const decoded = flags.map(item => atob(item));
const payload = "({ feature: decoded[0], theme: decoded[1] })";
const config = eval(payload);
console.log(config.feature, config.theme);
