"use strict";

// Flat config. Node CommonJS, focused on catching real mistakes (undeclared globals like the
// `for (Project of ...)` leak, unused vars) rather than style, which Prettier owns.
const globals = {
    process: "readonly", require: "readonly", module: "writable", exports: "writable",
    __dirname: "readonly", __filename: "readonly", console: "readonly", Buffer: "readonly",
    setTimeout: "readonly", clearTimeout: "readonly", setInterval: "readonly", clearInterval: "readonly",
    setImmediate: "readonly", URL: "readonly", fetch: "readonly", AbortSignal: "readonly",
    globalThis: "readonly"
};

module.exports = [
    {
        ignores: ["node_modules/**", "coverage/**", "files/**"]
    },
    {
        files: ["**/*.js"],
        languageOptions: {
            ecmaVersion: 2023,
            sourceType: "commonjs",
            globals
        },
        rules: {
            "no-undef": "error",
            "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
            "no-var": "error",
            "prefer-const": "warn",
            "no-implicit-globals": "error",
            eqeqeq: ["warn", "smart"],
            "no-throw-literal": "error"
        }
    },
    {
        files: ["tests/**/*.js"],
        languageOptions: {
            globals: { ...globals, global: "writable" }
        }
    }
];
