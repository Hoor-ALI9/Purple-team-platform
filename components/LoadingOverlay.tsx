'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore } from '@/lib/store'

export default function LoadingOverlay() {
  const { isLoading, loadingMessage } = usePurpleTeamStore()

  return (
    <AnimatePresence>
      {isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-void/90 backdrop-blur-sm z-50 flex items-center justify-center"
        >
          <div className="text-center">
            {/* Cyber Loading Animation */}
            <div className="relative w-32 h-32 mx-auto mb-8">
              {/* Outer Ring */}
              <motion.div
                className="absolute inset-0 rounded-full border-2 border-cyber-purple/30"
                animate={{ rotate: 360 }}
                transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
              />
              {/* Middle Ring */}
              <motion.div
                className="absolute inset-2 rounded-full border-2 border-cyber-magenta/50"
                animate={{ rotate: -360 }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              />
              {/* Inner Ring */}
              <motion.div
                className="absolute inset-4 rounded-full border-2 border-cyber-violet"
                style={{
                  borderTopColor: 'transparent',
                  borderRightColor: 'transparent',
                }}
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              />
              {/* Center Pulse */}
              <motion.div
                className="absolute inset-8 rounded-full bg-cyber-purple/20"
                animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              />
              {/* Center Dot */}
              <div className="absolute inset-12 rounded-full bg-cyber-purple flex items-center justify-center">
                <div className="w-2 h-2 bg-white rounded-full" />
              </div>
            </div>

            {/* Loading Text */}
            <motion.h2
              className="font-display text-2xl font-bold tracking-widest text-cyber-purple mb-2"
              animate={{ opacity: [0.5, 1, 0.5] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            >
              PROCESSING
            </motion.h2>
            <p className="text-slate font-mono text-sm">
              {loadingMessage || 'Executing operation...'}
            </p>

            {/* Progress Bar */}
            <div className="w-64 h-1 bg-graphite rounded-full mx-auto mt-6 overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-cyber-purple to-cyber-magenta"
                animate={{ x: ['-100%', '100%'] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
              />
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

