const fallbackConfig = "{ \"theme\": \"light\", \"region\": \"us-west\" }";
const runtimeConfig = eval("(" + fallbackConfig + ")");
window.location.hash = runtimeConfig.region;
console.log("Loaded config", runtimeConfig.theme);
