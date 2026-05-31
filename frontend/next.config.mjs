/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  distDir: 'out',
  trailingSlash: true,
  turbopack: {
    root: import.meta.dirname,
  },
  images: {
    unoptimized: true,
  },
}

export default nextConfig
