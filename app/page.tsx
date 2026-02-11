'use client'

import { useEffect, useState, Suspense } from 'react'
import dynamic from 'next/dynamic'
import { motion } from 'framer-motion'
import Sidebar from '@/components/Sidebar'
import Header from '@/components/Header'
import LoadingOverlay from '@/components/LoadingOverlay'
import { usePurpleTeamStore } from '@/lib/store'

// Dynamically import all page components for code splitting
const PentestPage = dynamic(() => import('@/components/pages/PentestPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const AIIngestPage = dynamic(() => import('@/components/pages/AIIngestPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const AIRemediationPage = dynamic(() => import('@/components/pages/AIRemediationPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const AISIEMRulesPage = dynamic(() => import('@/components/pages/AISIEMRulesPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const ThreatIntelPage = dynamic(() => import('@/components/pages/ThreatIntelPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const AlertsPage = dynamic(() => import('@/components/pages/AlertsPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

const SettingsPage = dynamic(() => import('@/components/pages/SettingsPage'), {
  loading: () => <PageSkeleton />,
  ssr: false,
})

// Loading skeleton component
function PageSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-8 bg-graphite/30 rounded w-1/3"></div>
      <div className="h-64 bg-graphite/20 rounded"></div>
      <div className="h-32 bg-graphite/20 rounded"></div>
    </div>
  )
}

export default function Home() {
  const { activeTab } = usePurpleTeamStore()
  const [currentTime, setCurrentTime] = useState('')

  useEffect(() => {
    // Optimize time updates - only update when tab is visible
    const updateTime = () => {
      if (!document.hidden) {
        setCurrentTime(new Date().toISOString())
      }
    }
    updateTime()
    const interval = setInterval(updateTime, 1000)
    return () => clearInterval(interval)
  }, [])

  const renderContent = () => {
    switch (activeTab) {
      case 'pentest-credentialed':
        return <PentestPage mode="credentialed" />
      case 'pentest-blackbox':
        return <PentestPage mode="blackbox" />
      case 'ai-ingest':
        return <AIIngestPage />
      case 'ai-remediation':
        return <AIRemediationPage />
      case 'ai-rules':
        return <AISIEMRulesPage />
      case 'threat-intel':
        return <ThreatIntelPage />
      case 'alerts':
        return <AlertsPage />
      case 'settings':
        return <SettingsPage />
      default:
        return <PentestPage mode="blackbox" />
    }
  }

  return (
    <div className="min-h-screen bg-void cyber-grid-bg">
      <LoadingOverlay />
      <Sidebar />
      
      {/* Main Content */}
      <main className="lg:ml-[280px] min-h-screen">
        <Header />
        
        <div className="p-6">
          <Suspense fallback={<PageSkeleton />}>
            <motion.div
              key={activeTab}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.15, ease: 'easeOut' }}
            >
              {renderContent()}
            </motion.div>
          </Suspense>
        </div>

        {/* Footer */}
        <footer className="border-t border-slate/20 p-4 mt-8">
          <div className="flex items-center justify-between text-xs text-slate">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
              <span className="font-mono">PURPLE TEAM OPS v1.0.0</span>
            </div>
            <div className="font-mono">
              {currentTime || '\u00A0'}
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}

