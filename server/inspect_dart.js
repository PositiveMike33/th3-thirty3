
const dart = require('dart-tools');
console.log("Keys:", Object.keys(dart));
if (dart.OpenAPI) {
    console.log("OpenAPI Config:", dart.OpenAPI);
}
if (dart.TaskService) {
    console.log("TaskService keys:", Object.keys(dart.TaskService));
}
