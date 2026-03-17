'use client'

import { useState, useEffect } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import nacl from 'tweetnacl'
import { deriveEncryptionKeypair, loadKeypair, saveKeypair, clearKeypair } from '@/lib/crypto'
import ConversationList from './ConversationList'
import ChatView from './ChatView'

export default function Inbox() {
  const { activeAddress, signTransactions } = useWallet()
  const [keypair, setKeypair] = useState<nacl.BoxKeyPair | null>(null)
  const [unlocking, setUnlocking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)

  // Auto-restore keypair from localStorage
  useEffect(() => {
    if (!activeAddress) return
    const stored = loadKeypair(activeAddress)
    if (stored) setKeypair(stored)
  }, [activeAddress])

  async function handleUnlock() {
    if (!activeAddress) return
    setUnlocking(true)
    setError(null)
    try {
      const kp = await deriveEncryptionKeypair(
        (txns) => signTransactions(txns),
        activeAddress
      )
      setKeypair(kp)
      saveKeypair(activeAddress, kp)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to unlock'
      setError(msg)
    } finally {
      setUnlocking(false)
    }
  }

  if (!activeAddress) {
    return (
      <div className="inbox-empty">
        <p>Connect your wallet to see your messages.</p>
      </div>
    )
  }

  if (!keypair) {
    return (
      <div className="inbox">
        <div className="inbox-header">
          <h3>Inbox</h3>
          <button
            className="btn btn-primary"
            onClick={handleUnlock}
            disabled={unlocking}
          >
            {unlocking ? 'Signing...' : 'Unlock'}
          </button>
        </div>
        {error && <p className="error-msg">{error}</p>}
        <div className="inbox-empty">
          <p>Sign a transaction to unlock your encrypted inbox.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="inbox">
      {selectedPeer ? (
        <ChatView
          activeAddress={activeAddress}
          peerAddress={selectedPeer}
          keypair={keypair}
          onBack={() => setSelectedPeer(null)}
        />
      ) : (
        <>
          <div className="inbox-header">
            <h3>Conversations</h3>
            <div className="inbox-actions">
              <button
                className="btn btn-secondary"
                onClick={() => {
                  if (activeAddress) clearKeypair(activeAddress)
                  setKeypair(null)
                }}
              >
                Lock
              </button>
            </div>
          </div>
          <ConversationList
            activeAddress={activeAddress}
            onSelectPeer={setSelectedPeer}
          />
        </>
      )}
    </div>
  )
}
