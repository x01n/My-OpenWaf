import type { NextConfig } from "next"

const nextConfig: NextConfig = {
  output: "export",
  distDir: "out",
  trailingSlash: true,
  poweredByHeader: false,
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  experimental: {
    optimizePackageImports: ["lucide-react", "date-fns"],
  },
}

export default nextConfig