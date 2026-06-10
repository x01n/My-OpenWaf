import type { NextConfig } from "next"
import { PHASE_DEVELOPMENT_SERVER } from "next/constants"
import path from "node:path"

function adminApiOrigin() {
  const bind = process.env.MY_OPENWAF_ADMIN_BIND?.trim() || ":9443"

  if (bind.startsWith("http://") || bind.startsWith("https://")) {
    return bind.replace(/\/$/, "")
  }

  const hostPort = bind.startsWith(":") ? `127.0.0.1${bind}` : bind

  return `http://${hostPort}`
}

const staticExportConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  skipTrailingSlashRedirect: true,
  turbopack: {
    root: path.resolve(__dirname),
  },
}

export default function nextConfig(phase: string): NextConfig {
  if (phase === PHASE_DEVELOPMENT_SERVER) {
    return {
      skipTrailingSlashRedirect: true,
      turbopack: staticExportConfig.turbopack,
      async rewrites() {
        return [
          {
            source: "/api/v1/:path*",
            destination: `${adminApiOrigin()}/api/v1/:path*`,
          },
        ]
      },
    }
  }

  return staticExportConfig
}
