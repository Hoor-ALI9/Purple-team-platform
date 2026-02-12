'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore } from '@/lib/store'
import {
  ShieldCheckIcon,
  CpuChipIcon,
  GlobeAltIcon,
  BellAlertIcon,
  Cog6ToothIcon,
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  CommandLineIcon,
  DocumentMagnifyingGlassIcon,
  WrenchScrewdriverIcon,
  ShieldExclamationIcon,
  Bars3Icon,
  XMarkIcon,
  BugAntIcon,
} from '@heroicons/react/24/outline'

const navigation = [
  {
    id: 'pentest',
    name: 'PENTEST',
    icon: CommandLineIcon,
    description: 'Execute penetration tests',
    color: 'from-cyber-purple to-cyber-magenta',
    subItems: [
      { id: 'pentest-credentialed', name: 'Credentialed' },
      { id: 'pentest-blackbox', name: 'Black Box' },
    ],
  },
  {
    id: 'ai',
    name: 'AI ANALYSIS',
    icon: CpuChipIcon,
    description: 'AI-powered security insights',
    color: 'from-cyber-blue to-cyber-cyan',
    subItems: [
      { id: 'ai-ingest', name: 'Ingest & Report' },
      { id: 'ai-remediation', name: 'Remediation' },
      { id: 'ai-rules', name: 'SIEM Rules' },
      { id: 'ai-cve-results', name: 'CVE Results' },
    ],
  },
  {
    id: 'threat-intel',
    name: 'THREAT INTEL',
    icon: GlobeAltIcon,
    description: 'Threat intelligence feeds',
    color: 'from-neon-orange to-neon-yellow',
  },
  {
    id: 'alerts',
    name: 'ALERTS',
    icon: BellAlertIcon,
    description: 'Security alerts & tuning',
    color: 'from-neon-red to-neon-orange',
  },
  {
    id: 'settings',
    name: 'SETTINGS',
    icon: Cog6ToothIcon,
    description: 'Platform configuration',
    color: 'from-slate to-graphite',
  },
]

export default function Sidebar() {
  const { activeTab, setActiveTab } = usePurpleTeamStore()
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [expandedItem, setExpandedItem] = useState<string | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleNavClick = (item: (typeof navigation)[0]) => {
    if (item.subItems) {
      setExpandedItem(expandedItem === item.id ? null : item.id)
      if (!expandedItem || expandedItem !== item.id) {
        setActiveTab(item.subItems[0].id)
      }
    } else {
      setActiveTab(item.id)
      setExpandedItem(null)
    }
  }

  const isActive = (itemId: string) => {
    const item = navigation.find((n) => n.id === itemId)
    if (item?.subItems) {
      return item.subItems.some((sub) => sub.id === activeTab)
    }
    return activeTab === itemId
  }

  // Extracted as plain JSX instead of an inline component to avoid remount cycles
  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="p-6 border-b border-slate/20">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-purple to-cyber-magenta flex items-center justify-center">
              <ShieldCheckIcon className="w-7 h-7 text-white" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-neon-green rounded-full border-2 border-obsidian animate-pulse" />
          </div>
          {!isCollapsed && (
            <div>
              <h1 className="font-display font-bold text-xl tracking-wider text-white">
                PURPLE<span className="text-cyber-purple">TEAM</span>
              </h1>
              <p className="text-xs text-slate tracking-widest uppercase">OPS Platform</p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-6 px-3 space-y-2 overflow-y-auto">
        {navigation.map((item) => {
          const Icon = item.icon
          const active = isActive(item.id)

          return (
            <div key={item.id}>
              <button
                onClick={() => handleNavClick(item)}
                className={`
                  w-full flex items-center gap-3 px-4 py-3 rounded-xl
                  transition-all duration-200 group relative
                  ${
                    active
                      ? 'bg-gradient-to-r ' + item.color + ' text-white shadow-lg'
                      : 'text-slate hover:text-white hover:bg-graphite/50'
                  }
                `}
              >
                <Icon className={`w-5 h-5 ${active ? 'text-white' : 'group-hover:text-cyber-purple'}`} />
                {!isCollapsed && (
                  <>
                    <span className="font-display font-semibold tracking-wider text-sm flex-1 text-left">
                      {item.name}
                    </span>
                    {item.subItems && (
                      <svg
                        className={`w-4 h-4 transition-transform duration-200 ${expandedItem === item.id ? 'rotate-180' : ''}`}
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    )}
                  </>
                )}
                {active && (
                  <div
                    className="absolute left-0 w-1 h-8 bg-white rounded-r-full"
                    style={{ top: '50%', transform: 'translateY(-50%)' }}
                  />
                )}
              </button>

              {/* Sub Items */}
              {item.subItems && expandedItem === item.id && !isCollapsed && (
                <div className="ml-4 mt-1 space-y-1 overflow-hidden">
                  {item.subItems.map((subItem) => (
                    <button
                      key={subItem.id}
                      onClick={() => setActiveTab(subItem.id)}
                      className={`
                        w-full flex items-center gap-2 px-4 py-2 rounded-lg text-sm
                        transition-all duration-150
                        ${
                          activeTab === subItem.id
                            ? 'text-cyber-purple bg-cyber-purple/10 border-l-2 border-cyber-purple'
                            : 'text-slate hover:text-white hover:bg-graphite/30 border-l-2 border-transparent'
                        }
                      `}
                    >
                      <div className={`w-1.5 h-1.5 rounded-full ${activeTab === subItem.id ? 'bg-cyber-purple' : 'bg-slate'}`} />
                      <span className="font-display tracking-wider">{subItem.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* Collapse Button */}
      <div className="p-4 border-t border-slate/20">
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="w-full flex items-center justify-center gap-2 py-2 text-slate hover:text-white transition-colors"
        >
          {isCollapsed ? (
            <ChevronDoubleRightIcon className="w-5 h-5" />
          ) : (
            <>
              <ChevronDoubleLeftIcon className="w-5 h-5" />
              <span className="text-xs font-display tracking-wider">COLLAPSE</span>
            </>
          )}
        </button>
      </div>

      {/* Status */}
      {!isCollapsed && (
        <div className="p-4 mx-3 mb-3 rounded-xl bg-gradient-to-br from-graphite to-obsidian border border-slate/20">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
            <span className="text-xs font-display tracking-wider text-neon-green">SYSTEM ONLINE</span>
          </div>
          <p className="text-xs text-slate">n8n Connected • Elastic Active</p>
        </div>
      )}
    </div>
  )

  return (
    <>
      {/* Mobile Toggle */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-obsidian border border-slate/30"
      >
        <Bars3Icon className="w-6 h-6 text-white" />
      </button>

      {/* Mobile Overlay */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="lg:hidden fixed inset-0 bg-void/80 backdrop-blur-sm z-40"
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.aside
            initial={{ x: -300 }}
            animate={{ x: 0 }}
            exit={{ x: -300 }}
            transition={{ type: 'spring', damping: 25 }}
            className="lg:hidden fixed left-0 top-0 h-screen w-72 bg-obsidian border-r border-slate/20 z-50"
          >
            <button
              onClick={() => setMobileOpen(false)}
              className="absolute top-4 right-4 p-2 text-slate hover:text-white"
            >
              <XMarkIcon className="w-6 h-6" />
            </button>
            {sidebarContent}
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: isCollapsed ? 80 : 280 }}
        transition={{ duration: 0.2 }}
        className="hidden lg:block fixed left-0 top-0 h-screen bg-obsidian border-r border-slate/20 z-30"
      >
        {sidebarContent}
      </motion.aside>
    </>
  )
}
