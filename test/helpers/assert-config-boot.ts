// Boots `assertConfig` in a process of its own, so a test can observe whether it
// EXITS. That is the only way to assert it: `assertConfig` calls
// `process.exit(1)`, which no in-process assertion can survive.
//
// Driven by apns-config.test.ts. `__NEEDS__` is the `needs` array as JSON.
import { assertConfig, type ConfigNeed } from "../../lib/config";

assertConfig(JSON.parse(process.env.__NEEDS__ || "[]") as ConfigNeed[]);
console.log("booted");
