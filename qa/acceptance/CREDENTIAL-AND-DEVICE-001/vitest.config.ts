export default {
  resolve: {
    alias: {
      "@neondatabase/serverless": "../../qa/acceptance/CREDENTIAL-AND-DEVICE-001/external-neon.ts",
      postgres: "../../qa/acceptance/CREDENTIAL-AND-DEVICE-001/external-postgres.ts",
    },
  },
  test: {
    include: ["../../qa/acceptance/CREDENTIAL-AND-DEVICE-001/worker_device_acceptance.test.ts"],
    environment: "node",
    globals: true,
  },
};
