'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore } from '@/lib/store'
import {
  BellIcon,
  UserCircleIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline'
import { format } from 'date-fns'

export default function Header() {
  const { notifications, clearNotifications } = usePurpleTeamStore()
  const [showNotifications, setShowNotifications] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'success':
        return <CheckCircleIcon className="w-5 h-5 text-neon-green" />
      case 'error':
        return <ExclamationTriangleIcon className="w-5 h-5 text-neon-red" />
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5 text-neon-yellow" />
      default:
        return <InformationCircleIcon className="w-5 h-5 text-cyber-purple" />
    }
  }

  return (
    <header className="sticky top-0 z-20 bg-obsidian/80 backdrop-blur-xl border-b border-slate/20">
      <div className="flex items-center justify-between px-6 py-4">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate" />
          <input
            type="text"
            placeholder="Search operations, alerts, rules..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-graphite/50 border border-slate/30 rounded-xl
                       text-white placeholder:text-slate font-mono text-sm
                       focus:outline-none focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple/50
                       transition-all duration-200"
          />
        </div>

        {/* Right Section */}
        <div className="flex items-center gap-4 ml-6">
          {/* Status Indicators */}
          <div className="hidden md:flex items-center gap-4 px-4 py-2 bg-graphite/30 rounded-lg">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
              <span className="text-xs font-mono text-slate">n8n</span>
            </div>
            <div className="w-px h-4 bg-slate/30" />
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-cyber-cyan rounded-full animate-pulse" />
              <span className="text-xs font-mono text-slate">Elastic</span>
            </div>
            <div className="w-px h-4 bg-slate/30" />
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-cyber-purple rounded-full animate-pulse" />
              <span className="text-xs font-mono text-slate">Discord</span>
            </div>
          </div>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-lg hover:bg-graphite/50 transition-colors"
            >
              <BellIcon className="w-6 h-6 text-slate hover:text-white transition-colors" />
              {notifications.length > 0 && (
                <span className="absolute -top-1 -right-1 w-5 h-5 bg-neon-red rounded-full 
                               flex items-center justify-center text-xs font-bold text-white">
                  {notifications.length > 9 ? '9+' : notifications.length}
                </span>
              )}
            </button>

            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="absolute right-0 top-full mt-2 w-96 bg-obsidian border border-slate/30 
                             rounded-xl shadow-2xl overflow-hidden z-50"
                >
                  <div className="flex items-center justify-between px-4 py-3 border-b border-slate/20">
                    <h3 className="font-display font-semibold tracking-wider text-white">
                      NOTIFICATIONS
                    </h3>
                    <button
                      onClick={clearNotifications}
                      className="text-xs text-slate hover:text-cyber-purple transition-colors"
                    >
                      Clear All
                    </button>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="py-8 text-center text-slate">
                        <BellIcon className="w-8 h-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">No notifications</p>
                      </div>
                    ) : (
                      notifications.map((notification) => (
                        <div
                          key={notification.id}
                          className="px-4 py-3 border-b border-slate/10 hover:bg-graphite/30 transition-colors"
                        >
                          <div className="flex items-start gap-3">
                            {getNotificationIcon(notification.type)}
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold text-white truncate">
                                {notification.title}
                              </p>
                              <p className="text-xs text-slate mt-1">
                                {notification.message}
                              </p>
                              <p className="text-xs text-slate/50 mt-1">
                                {format(new Date(notification.timestamp), 'HH:mm:ss')}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* User */}
          <button className="flex items-center gap-2 p-2 rounded-lg hover:bg-graphite/50 transition-colors">
            <UserCircleIcon className="w-8 h-8 text-cyber-purple" />
            <span className="hidden md:block text-sm font-display tracking-wider text-white">
              OPERATOR
            </span>
          </button>
        </div>
      </div>
    </header>
  )
}

