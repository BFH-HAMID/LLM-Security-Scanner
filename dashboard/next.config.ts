import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // A self-contained server bundle keeps the Docker image small (the Dockerfile sets this).
  // Plain `npm run build && npm start` uses the regular output.
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  poweredByHeader: false,
  reactStrictMode: true,
  // Only relevant to `next dev` behind a proxy / preview host.
  allowedDevOrigins: (process.env.DASHBOARD_ALLOWED_DEV_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
