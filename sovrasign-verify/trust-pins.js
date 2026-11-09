// The trust-list keys a build pins and the signed list bundled with it. The service's own build
// writes this file with the keys of its environment; this copy is a build without pins, which
// starts from the service's published list when it is served by the service, else from the
// engine's built-in list (verify.js, initTrust).
export const TRUST = { env: "none", pins: [], bundle: null };
