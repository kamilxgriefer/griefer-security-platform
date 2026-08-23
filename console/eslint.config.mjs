import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescriptConfig from "eslint-config-next/typescript";

const config = [
  {
    ignores: [".next/**", "node_modules/**", "next-env.d.ts", "coverage/**"],
  },
  ...coreWebVitals,
  ...typescriptConfig,
  {
    rules: {
      // The console renders untrusted incident data. Anything that writes raw
      // HTML into the DOM is a stored-XSS vector, and must be a deliberate,
      // reviewed decision rather than a convenience.
      "react/no-danger": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-console": ["warn", { allow: ["warn", "error"] }],
      eqeqeq: ["error", "always"],
    },
  },
];

export default config;
