'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore, RemediationStep } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  WrenchScrewdriverIcon,
  CheckIcon,
  XMarkIcon,
  PencilIcon,
  PlayIcon,
  PlusIcon,
  TrashIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'

export default function AIRemediationPage() {
  const { 
    currentAnalysis, 
    n8nConfig, 
    updateRemediationStatus, 
    updateRemediationCommand,
    addRemediationStep,
    removeRemediationStep,
    setIsLoading,
    setLoadingMessage,
    addNotification,
  } = usePurpleTeamStore()
  
  const [editingStep, setEditingStep] = useState<string | null>(null)
  const [editedCommand, setEditedCommand] = useState('')
  const [activePhase, setActivePhase] = useState<'immediate' | 'short_term' | 'long_term'>('immediate')

  const [showAddModal, setShowAddModal] = useState(false)
  const [newStep, setNewStep] = useState({
    title: '',
    description: '',
    command: '',
    target_scope: 'endpoint',
    expected_outcome: '',
    risk_if_skipped: '',
    requires_approval: true,
    is_disruptive: false,
  })

  const handleEditClick = (step: RemediationStep) => {
    setEditingStep(step.id)
    setEditedCommand(step.command)
  }

  const handleSaveEdit = (stepId: string) => {
    if (currentAnalysis) {
      updateRemediationCommand(currentAnalysis.execution_id, stepId, editedCommand)
      setEditingStep(null)
      toast.success('Command updated')
    }
  }

  const handleApprove = async (step: RemediationStep) => {
    if (!currentAnalysis) return

    // First update status to approved
    updateRemediationStatus(currentAnalysis.execution_id, step.id, 'approved')
    
    // Then execute via n8n
    setIsLoading(true)
    setLoadingMessage(`Executing remediation: ${step.title}...`)

    try {
      const webhookUrl = `${n8nConfig.base_url}${n8nConfig.webhook_remediation}`
      
      const payload = {
        execution_id: currentAnalysis.execution_id,
        step_id: step.id,
        command: step.command,
        target_scope: step.target_scope,
        ssh_host: n8nConfig.ssh_host,
        ssh_user: n8nConfig.ssh_user,
        timestamp: new Date().toISOString(),
      }

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (response.ok) {
        updateRemediationStatus(currentAnalysis.execution_id, step.id, 'executed')
        
        addNotification({
          id: `notif_${Date.now()}`,
          type: 'success',
          title: 'Remediation Executed',
          message: `${step.title} completed successfully`,
          timestamp: new Date().toISOString(),
        })

        toast.success('Remediation executed successfully')
      } else {
        throw new Error('Execution failed')
      }
    } catch (error) {
      updateRemediationStatus(currentAnalysis.execution_id, step.id, 'pending')
      toast.error('Failed to execute remediation')
    } finally {
      setIsLoading(false)
      setLoadingMessage('')
    }
  }

  const handleReject = (stepId: string) => {
    if (currentAnalysis) {
      updateRemediationStatus(currentAnalysis.execution_id, stepId, 'rejected')
      toast.success('Remediation step rejected')
    }
  }

  const handleAddManualStep = () => {
    if (!currentAnalysis) return
    if (!newStep.title.trim() || !newStep.command.trim()) {
      toast.error('Title and command are required')
      return
    }

    const step: RemediationStep = {
      id: `manual_${Date.now()}`,
      title: newStep.title.trim(),
      description: newStep.description.trim() || 'Manual remediation step',
      command: newStep.command,
      target_scope: newStep.target_scope.trim() || 'endpoint',
      expected_outcome: newStep.expected_outcome.trim() || 'N/A',
      risk_if_skipped: newStep.risk_if_skipped.trim() || 'N/A',
      requires_approval: !!newStep.requires_approval,
      is_disruptive: !!newStep.is_disruptive,
      status: 'pending',
    }

    addRemediationStep(currentAnalysis.execution_id, activePhase, step)
    setShowAddModal(false)
    setNewStep({
      title: '',
      description: '',
      command: '',
      target_scope: 'endpoint',
      expected_outcome: '',
      risk_if_skipped: '',
      requires_approval: true,
      is_disruptive: false,
    })
    toast.success('Manual remediation step added')
  }

  const handleDeleteStep = (stepId: string) => {
    if (!currentAnalysis) return
    removeRemediationStep(currentAnalysis.execution_id, activePhase, stepId)
    toast.success('Step deleted')
  }

  const getPhaseSteps = () => {
    if (!currentAnalysis) return []
    return currentAnalysis.remediation[activePhase]
  }

  const getStatusBadge = (status: RemediationStep['status']) => {
    switch (status) {
      case 'pending':
        return <span className="cyber-badge bg-slate/20 text-slate border-slate/30">PENDING</span>
      case 'approved':
        return <span className="cyber-badge-purple">APPROVED</span>
      case 'executed':
        return <span className="cyber-badge-green">EXECUTED</span>
      case 'rejected':
        return <span className="cyber-badge-red">REJECTED</span>
    }
  }

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'immediate':
        return <ExclamationTriangleIcon className="w-5 h-5" />
      case 'short_term':
        return <ClockIcon className="w-5 h-5" />
      case 'long_term':
        return <ShieldCheckIcon className="w-5 h-5" />
      default:
        return null
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <WrenchScrewdriverIcon className="w-8 h-8 text-neon-green" />
            REMEDIATION STEPS
          </h1>
          <p className="text-slate mt-1">
            Review, edit, and execute remediation commands with human approval
          </p>
        </div>
        {currentAnalysis && (
          <motion.button
            onClick={() => setShowAddModal(true)}
            className="cyber-btn flex items-center gap-2"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            <PlusIcon className="w-5 h-5" />
            ADD MANUAL STEP
          </motion.button>
        )}
      </div>

      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="cyber-card w-full max-w-2xl rounded-2xl p-6"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                  ADD MANUAL REMEDIATION STEP
                </h2>
                <p className="text-sm text-slate mt-1">
                  This step will be added to the current phase and can be executed via n8n.
                </p>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate hover:text-white transition-colors"
              >
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="text-xs font-display tracking-wider text-slate">TITLE *</label>
                <input
                  value={newStep.title}
                  onChange={(e) => setNewStep((s) => ({ ...s, title: e.target.value }))}
                  className="cyber-input"
                />
              </div>

              <div className="md:col-span-2">
                <label className="text-xs font-display tracking-wider text-slate">DESCRIPTION</label>
                <input
                  value={newStep.description}
                  onChange={(e) => setNewStep((s) => ({ ...s, description: e.target.value }))}
                  className="cyber-input"
                />
              </div>

              <div className="md:col-span-2">
                <label className="text-xs font-display tracking-wider text-slate">COMMAND *</label>
                <textarea
                  value={newStep.command}
                  onChange={(e) => setNewStep((s) => ({ ...s, command: e.target.value }))}
                  className="cyber-input font-mono text-sm"
                  rows={4}
                />
              </div>

              <div>
                <label className="text-xs font-display tracking-wider text-slate">TARGET SCOPE</label>
                <input
                  value={newStep.target_scope}
                  onChange={(e) => setNewStep((s) => ({ ...s, target_scope: e.target.value }))}
                  className="cyber-input"
                />
              </div>

              <div>
                <label className="text-xs font-display tracking-wider text-slate">EXPECTED OUTCOME</label>
                <input
                  value={newStep.expected_outcome}
                  onChange={(e) => setNewStep((s) => ({ ...s, expected_outcome: e.target.value }))}
                  className="cyber-input"
                />
              </div>

              <div className="md:col-span-2">
                <label className="text-xs font-display tracking-wider text-slate">RISK IF SKIPPED</label>
                <input
                  value={newStep.risk_if_skipped}
                  onChange={(e) => setNewStep((s) => ({ ...s, risk_if_skipped: e.target.value }))}
                  className="cyber-input"
                />
              </div>
            </div>

            <div className="flex items-center gap-6 mt-4">
              <label className="flex items-center gap-2 text-sm text-slate">
                <input
                  type="checkbox"
                  checked={newStep.requires_approval}
                  onChange={(e) => setNewStep((s) => ({ ...s, requires_approval: e.target.checked }))}
                />
                Requires approval
              </label>
              <label className="flex items-center gap-2 text-sm text-slate">
                <input
                  type="checkbox"
                  checked={newStep.is_disruptive}
                  onChange={(e) => setNewStep((s) => ({ ...s, is_disruptive: e.target.checked }))}
                />
                Disruptive
              </label>
            </div>

            <div className="flex gap-2 mt-6">
              <motion.button
                onClick={handleAddManualStep}
                className="cyber-btn-success flex-1"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                ADD STEP
              </motion.button>
              <motion.button
                onClick={() => setShowAddModal(false)}
                className="cyber-btn-outline px-6"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                CANCEL
              </motion.button>
            </div>
          </motion.div>
        </div>
      )}

      {currentAnalysis ? (
        <>
          {/* Phase Tabs */}
          <div className="flex gap-2 p-1 bg-obsidian rounded-xl border border-slate/20">
            {(['immediate', 'short_term', 'long_term'] as const).map((phase) => (
              <button
                key={phase}
                onClick={() => setActivePhase(phase)}
                className={`
                  flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg
                  font-display font-semibold tracking-wider text-sm transition-all duration-200
                  ${activePhase === phase
                    ? phase === 'immediate'
                      ? 'bg-neon-red/20 text-neon-red border border-neon-red/30'
                      : phase === 'short_term'
                      ? 'bg-neon-yellow/20 text-neon-yellow border border-neon-yellow/30'
                      : 'bg-neon-green/20 text-neon-green border border-neon-green/30'
                    : 'text-slate hover:text-white hover:bg-graphite/30'
                  }
                `}
              >
                {getPhaseIcon(phase)}
                {phase.replace('_', ' ').toUpperCase()}
                <span className="w-6 h-6 rounded-full bg-current/20 text-xs flex items-center justify-center">
                  {currentAnalysis.remediation[phase].length}
                </span>
              </button>
            ))}
          </div>

          {/* Steps List */}
          <div className="space-y-4">
            <AnimatePresence mode="wait">
              {getPhaseSteps().length === 0 ? (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="cyber-card rounded-2xl p-12 text-center"
                >
                  <WrenchScrewdriverIcon className="w-12 h-12 mx-auto mb-4 text-slate opacity-50" />
                  <p className="text-slate">No remediation steps in this phase</p>
                </motion.div>
              ) : (
                getPhaseSteps().map((step, index) => (
                  <motion.div
                    key={step.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ delay: index * 0.1 }}
                    className="cyber-card rounded-2xl p-6"
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="font-display text-lg font-semibold tracking-wider text-white">
                            {step.title}
                          </h3>
                          {step.requires_approval && (
                            <span className="cyber-badge-yellow text-xs">REQUIRES APPROVAL</span>
                          )}
                          {step.is_disruptive && (
                            <span className="cyber-badge-red text-xs">DISRUPTIVE</span>
                          )}
                        </div>
                        <p className="text-slate">{step.description}</p>
                      </div>
                      {getStatusBadge(step.status)}
                    </div>

                    {/* Details Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div className="p-3 bg-graphite/30 rounded-lg">
                        <span className="text-xs font-display tracking-wider text-slate">TARGET SCOPE</span>
                        <p className="text-white mt-1">{step.target_scope}</p>
                      </div>
                      <div className="p-3 bg-graphite/30 rounded-lg">
                        <span className="text-xs font-display tracking-wider text-slate">EXPECTED OUTCOME</span>
                        <p className="text-white mt-1">{step.expected_outcome}</p>
                      </div>
                      <div className="md:col-span-2 p-3 bg-neon-red/5 rounded-lg border border-neon-red/20">
                        <span className="text-xs font-display tracking-wider text-neon-red">RISK IF SKIPPED</span>
                        <p className="text-neon-red/80 mt-1">{step.risk_if_skipped}</p>
                      </div>
                    </div>

                    {/* Command */}
                    <div className="mb-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-display tracking-wider text-slate">COMMAND</span>
                        {editingStep !== step.id && step.status === 'pending' && (
                          <button
                            onClick={() => handleEditClick(step)}
                            className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                          >
                            <PencilIcon className="w-4 h-4" />
                            Edit
                          </button>
                        )}
                      </div>
                      
                      {editingStep === step.id ? (
                        <div className="space-y-2">
                          <textarea
                            value={editedCommand}
                            onChange={(e) => setEditedCommand(e.target.value)}
                            className="cyber-input font-mono text-sm"
                            rows={3}
                          />
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleSaveEdit(step.id)}
                              className="cyber-btn-success text-sm py-2 px-4"
                            >
                              Save
                            </button>
                            <button
                              onClick={() => setEditingStep(null)}
                              className="cyber-btn-outline text-sm py-2 px-4"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="code-block">
                          <code className="text-terminal">{step.command}</code>
                        </div>
                      )}
                    </div>

                    {/* Actions */}
                    {step.status === 'pending' && (
                      <div className="flex gap-3 pt-4 border-t border-slate/20">
                        <motion.button
                          onClick={() => handleApprove(step)}
                          className="flex-1 cyber-btn-success flex items-center justify-center gap-2"
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                        >
                          <CheckIcon className="w-5 h-5" />
                          APPROVE & EXECUTE
                        </motion.button>
                        <motion.button
                          onClick={() => handleDeleteStep(step.id)}
                          className="cyber-btn-outline flex items-center justify-center gap-2 px-6"
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                        >
                          <TrashIcon className="w-5 h-5" />
                          DELETE
                        </motion.button>
                        <motion.button
                          onClick={() => handleReject(step.id)}
                          className="cyber-btn-danger flex items-center justify-center gap-2 px-6"
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                        >
                          <XMarkIcon className="w-5 h-5" />
                          REJECT
                        </motion.button>
                      </div>
                    )}

                    {step.status === 'approved' && (
                      <div className="flex items-center gap-2 pt-4 border-t border-slate/20 text-cyber-purple">
                        <ArrowPathIcon className="w-5 h-5 animate-spin" />
                        <span className="font-display tracking-wider">Executing...</span>
                      </div>
                    )}

                    {step.status === 'executed' && (
                      <div className="flex items-center gap-2 pt-4 border-t border-slate/20 text-neon-green">
                        <CheckIcon className="w-5 h-5" />
                        <span className="font-display tracking-wider">Executed Successfully</span>
                      </div>
                    )}
                  </motion.div>
                ))
              )}
            </AnimatePresence>
          </div>
        </>
      ) : (
        <div className="cyber-card rounded-2xl p-12 text-center">
          <WrenchScrewdriverIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
          <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
            No Analysis Selected
          </h2>
          <p className="text-slate">
            Select an analysis from the Ingest page to view remediation steps
          </p>
        </div>
      )}
    </div>
  )
}

