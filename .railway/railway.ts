import {
  defineRailway,
  github,
  project,
  service,
  volume,
} from "railway/iac";

export default defineRailway(() => {
  const data = volume("relay-data", {
    region: "sfo",
    sizeMB: 5000,
  });

  const relay = service("omarchy-parentapproval", {
    source: github("aphexddb/omarchy-parentapproval", { branch: "main" }),
    build: {
      builder: "DOCKERFILE",
      dockerfilePath: "Dockerfile",
    },
    healthcheck: "/healthz",
    healthcheckTimeout: 30,
    replicas: { sfo: 1 },
    domains: [{ domain: "parentapprovals.com", port: 8080 }],
    env: {
      RELAY_DATA: "/data",
      RELAY_PUBLIC_URL: "https://parentapprovals.com",
    },
    volumeMounts: {
      "/data": data,
    },
  });

  return project("parentapprovals", {
    resources: [relay, data],
  });
});
