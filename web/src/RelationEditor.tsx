import { useEffect, useMemo, useState } from 'react'
import { Pencil, Trash2 } from 'lucide-react'
import { topologyEntityKey } from './frontend-utils'
import type { Device, NetworkNode, NetworkSegment, Relation } from './models'

export type RelationDraft = {
  sourceKind: string
  sourceId: string
  targetKind: string
  targetId: string
  relationType: string
  confidence: string
}

type EntityOption = {
  key: string
  kind: string
  id: string
  label: string
}

type RelationEditorProps = {
  devices: Device[]
  networkNodes: NetworkNode[]
  networkSegments: NetworkSegment[]
  relations: Relation[]
  busy: boolean
  errorMessage: string | null
  onSave: (draft: RelationDraft, relationId: string | null) => Promise<boolean>
  onDelete: (relation: Relation) => Promise<void>
}

const emptyDraft: RelationDraft = {
  sourceKind: '',
  sourceId: '',
  targetKind: '',
  targetId: '',
  relationType: 'connected_to',
  confidence: 'manual',
}

function relationEndpointLabel(relation: Relation, side: 'source' | 'target', labels: Map<string, string>): string {
  const kind = side === 'source' ? relation.sourceKind : relation.targetKind
  const id = side === 'source' ? relation.sourceId : relation.targetId
  return labels.get(topologyEntityKey(kind, id)) ?? `${kind}: ${id}`
}

export default function RelationEditor({
  devices,
  networkNodes,
  networkSegments,
  relations,
  busy,
  errorMessage,
  onSave,
  onDelete,
}: RelationEditorProps) {
  const options = useMemo<EntityOption[]>(
    () => [
      ...networkSegments.map((item) => ({ key: topologyEntityKey('networkSegment', item.id), kind: 'networkSegment', id: item.id, label: `Segment: ${item.name}` })),
      ...networkNodes.map((item) => ({ key: topologyEntityKey('networkNode', item.id), kind: 'networkNode', id: item.id, label: `Node: ${item.name}` })),
      ...devices.map((item) => ({ key: topologyEntityKey('device', item.id), kind: 'device', id: item.id, label: `Device: ${item.name}` })),
    ],
    [devices, networkNodes, networkSegments],
  )
  const optionByKey = useMemo(() => new Map(options.map((option) => [option.key, option])), [options])
  const labels = useMemo(() => new Map(options.map((option) => [option.key, option.label])), [options])
  const [draft, setDraft] = useState<RelationDraft>(emptyDraft)
  const [editingId, setEditingId] = useState<string | null>(null)

  useEffect(() => {
    setDraft((current) => {
      const currentSource = optionByKey.get(topologyEntityKey(current.sourceKind, current.sourceId))
      const currentTarget = optionByKey.get(topologyEntityKey(current.targetKind, current.targetId))
      if (currentSource && currentTarget) {
        return current
      }
      return {
        ...current,
        sourceKind: options[0]?.kind ?? '',
        sourceId: options[0]?.id ?? '',
        targetKind: options[1]?.kind ?? options[0]?.kind ?? '',
        targetId: options[1]?.id ?? options[0]?.id ?? '',
      }
    })
  }, [optionByKey, options])

  const setEndpoint = (side: 'source' | 'target', key: string) => {
    const option = optionByKey.get(key)
    if (!option) {
      return
    }
    setDraft((current) =>
      side === 'source'
        ? { ...current, sourceKind: option.kind, sourceId: option.id }
        : { ...current, targetKind: option.kind, targetId: option.id },
    )
  }

  const resetDraft = () => {
    setEditingId(null)
    setDraft({
      ...emptyDraft,
      sourceKind: options[0]?.kind ?? '',
      sourceId: options[0]?.id ?? '',
      targetKind: options[1]?.kind ?? options[0]?.kind ?? '',
      targetId: options[1]?.id ?? options[0]?.id ?? '',
    })
  }

  const startEditing = (relation: Relation) => {
    setEditingId(relation.id)
    setDraft({
      sourceKind: relation.sourceKind,
      sourceId: relation.sourceId,
      targetKind: relation.targetKind,
      targetId: relation.targetId,
      relationType: relation.relationType,
      confidence: relation.confidence || 'manual',
    })
  }

  const sourceKey = topologyEntityKey(draft.sourceKind, draft.sourceId)
  const targetKey = topologyEntityKey(draft.targetKind, draft.targetId)
  const canSubmit =
    options.length >= 2 &&
    topologyEntityKey(draft.sourceKind, draft.sourceId) !== topologyEntityKey(draft.targetKind, draft.targetId) &&
    Boolean(draft.relationType.trim()) &&
    !busy

  return (
    <div className="relation-editor">
      <form
        className="device-form"
        onSubmit={(event) => {
          event.preventDefault()
          if (canSubmit) {
            void onSave({ ...draft, relationType: draft.relationType.trim() }, editingId).then((saved) => {
              if (saved) {
                resetDraft()
              }
            })
          }
        }}
      >
        {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}
        {options.length < 2 ? <div className="form-note">At least two inventory entities are required to create a relation.</div> : null}
        <div className="form-grid">
          <label className="form-field">
            <span>Source</span>
            <select value={sourceKey} onChange={(event) => setEndpoint('source', event.target.value)} disabled={busy}>
              {options.map((option) => <option key={option.key} value={option.key}>{option.label}</option>)}
            </select>
          </label>
          <label className="form-field">
            <span>Target</span>
            <select value={targetKey} onChange={(event) => setEndpoint('target', event.target.value)} disabled={busy}>
              {options.map((option) => <option key={option.key} value={option.key}>{option.label}</option>)}
            </select>
          </label>
          <label className="form-field">
            <span>Relation type</span>
            <input
              value={draft.relationType}
              onChange={(event) => setDraft((current) => ({ ...current, relationType: event.target.value }))}
              placeholder="connected_to"
              disabled={busy}
            />
          </label>
          <label className="form-field">
            <span>Confidence</span>
            <select
              value={draft.confidence}
              onChange={(event) => setDraft((current) => ({ ...current, confidence: event.target.value }))}
              disabled={busy}
            >
              <option value="manual">Manual</option>
              <option value="observed">Observed</option>
              <option value="inferred">Inferred</option>
            </select>
          </label>
        </div>
        {draft.sourceId && sourceKey === targetKey ? <div className="inline-error" role="alert">Source and target must be different.</div> : null}
        <div className="form-actions">
          {editingId ? <button type="button" className="secondary-button" onClick={resetDraft} disabled={busy}>Cancel edit</button> : null}
          <button type="submit" className="action-button" disabled={!canSubmit}>
            {busy ? 'Saving...' : editingId ? 'Save relation' : 'Create relation'}
          </button>
        </div>
      </form>

      <div className="inventory-list relation-list">
        {relations.length === 0 ? <div className="empty-state">No relations</div> : relations.map((relation) => (
          <article key={relation.id} className="inventory-row relation-row">
            <div className="inventory-row__body">
              <div className="inventory-row__header">
                <strong>{relation.relationType}</strong>
                <span className="status-pill status-pill--mapped">{relation.confidence || 'unknown'}</span>
              </div>
              <p className="inventory-row__meta">
                <span className="inventory-row__meta-value">{relationEndpointLabel(relation, 'source', labels)}</span>
                <span aria-hidden="true"> {'->'} </span>
                <span className="inventory-row__meta-value">{relationEndpointLabel(relation, 'target', labels)}</span>
              </p>
            </div>
            <div className="inventory-row__header-actions relation-row__actions">
              <button type="button" className="icon-button icon-button--small" onClick={() => startEditing(relation)} disabled={busy} aria-label={`Edit ${relation.relationType} relation`} title="Edit relation"><Pencil aria-hidden="true" /></button>
              <button type="button" className="icon-danger-button" onClick={() => void onDelete(relation)} disabled={busy} aria-label={`Delete ${relation.relationType} relation`} title="Delete relation"><Trash2 aria-hidden="true" /></button>
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
