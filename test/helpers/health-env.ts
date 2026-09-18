// Thresholds for health-monitor.test.ts, set BEFORE the module under test loads.
//
// lib/health-monitor.ts reads its thresholds from the environment at import, so
// assigning process.env in the test file does not work: `import` is hoisted, so
// the module initialises — and reads the real defaults — before any statement in
// the test body runs. Putting the assignments in their own module and importing
// it FIRST is what orders them correctly, because imports execute in source
// order among themselves.
//
// Contained to one process: node --test runs each test file separately.
process.env.HEALTH_SAMPLE_MS = "150";
process.env.HEALTH_ERR_WARN = "3";
process.env.HEALTH_ERR_CRIT = "6";
process.env.HEALTH_ALERT_COOLDOWN_MS = "10000";
process.env.HEALTH_BACKPRESSURE_WARN = "2";
