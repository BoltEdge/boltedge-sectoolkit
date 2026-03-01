/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:5003/api/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
