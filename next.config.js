/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Optimize compiler settings
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },
  experimental: {
    serverActions: {
      allowedOrigins: ['localhost:3000'],
    },
    serverComponentsExternalPackages: ['ssh2'],
    // Enable faster refresh
    optimizePackageImports: ['@heroicons/react', 'framer-motion', 'recharts'],
  },
  webpack: (config, { isServer, dev }) => {
    if (isServer) {
      // ssh2 uses optional native crypto bindings - tell webpack to ignore them
      config.externals.push('ssh2')
    }
    
    // Enable webpack caching for faster rebuilds
    if (dev) {
      config.cache = {
        type: 'filesystem',
        buildDependencies: {
          config: [__filename],
        },
      }
    }
    
    return config
  },
}

module.exports = nextConfig

