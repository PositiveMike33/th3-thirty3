
const dart = require('dart-tools');
console.log("OpenAPI BASE:", dart.OpenAPI.BASE);
console.log("OpenAPI WITH_CREDENTIALS:", dart.OpenAPI.WITH_CREDENTIALS);
try {
    const propertyNames = Object.getOwnPropertyNames(dart.TaskService);
    console.log("TaskService props:", propertyNames);
} catch (e) {
    console.log("Error inspecting TaskService:", e.message);
}
