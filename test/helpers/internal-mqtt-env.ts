// MUST be imported before `auth/main`: it reads the internal MQTT identity into
// module constants at import, and `import` is hoisted above any test body.
export const INTERNAL_USER = "svc-internal-test";
export const INTERNAL_SECRET = "internal-secret-for-tests-only";
process.env.INTERNAL_MQTT_USER = INTERNAL_USER;
process.env.INTERNAL_MQTT_SECRET = INTERNAL_SECRET;
