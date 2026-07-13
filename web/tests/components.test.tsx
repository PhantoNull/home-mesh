import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import DraggableModal from '../src/DraggableModal'
import RelationEditor from '../src/RelationEditor'

describe('accessible modal markup', () => {
  it('exposes dialog semantics and an accessible title', () => {
    const markup = renderToStaticMarkup(
      <DraggableModal label="Inventory" title="Edit device" onClose={() => undefined}>
        <button type="button">Save</button>
      </DraggableModal>,
    )

    expect(markup).toContain('role="dialog"')
    expect(markup).toContain('aria-modal="true"')
    expect(markup).toMatch(/aria-labelledby="[^"]+"/)
    expect(markup).toMatch(/<h2 id="[^"]+">Edit device<\/h2>/)
  })
})

describe('relation editor', () => {
  it('keeps same-ID entities from different kinds selectable', () => {
    const markup = renderToStaticMarkup(
      <RelationEditor
        devices={[{
          id: 'shared', name: 'NAS', hostname: '', role: '', deviceType: '', ipAddress: '', macAddress: '',
          networkSegment: '', status: 'unknown', tags: [],
        }]}
        networkNodes={[{
          id: 'shared', name: 'Router', nodeType: 'router', managementIp: '', macAddress: '', vendor: '', model: '',
          status: 'unknown', tags: [],
        }]}
        networkSegments={[]}
        relations={[]}
        busy={false}
        errorMessage={null}
        onSave={async () => true}
        onDelete={async () => undefined}
      />,
    )

    expect(markup).toContain('Device: NAS')
    expect(markup).toContain('Node: Router')
    expect(markup).toContain('Create relation')
  })
})
