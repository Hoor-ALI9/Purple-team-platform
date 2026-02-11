import type { Metadata } from 'next'
import { Toaster } from 'react-hot-toast'
import './globals.css'

export const metadata: Metadata = {
  title: 'PURPLE TEAM OPS | Enterprise Security Platform',
  description: 'Enterprise-grade Purple Team automation platform for penetration testing, threat detection, and security operations',
  icons: {
    icon: '/favicon.ico',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-void antialiased">
        <Toaster
          position="top-right"
          toastOptions={{
            className: 'toast-cyber',
            duration: 4000,
            style: {
              background: '#1a1a24',
              color: '#fff',
              border: '1px solid rgba(168, 85, 247, 0.3)',
            },
            success: {
              iconTheme: {
                primary: '#22c55e',
                secondary: '#fff',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#fff',
              },
            },
          }}
        />
        {children}
      </body>
    </html>
  )
}

