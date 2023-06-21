/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    async rewrites() {
        return [
            {
                source: '/api/v1/:path*',
                destination: 'http://0.0.0.0:3001/:path*'
            }
        ]
    }
};

module.exports = nextConfig;
