import ELK from 'elkjs/lib/elk-api.js'
import elkWorkerUrl from 'elkjs/lib/elk-worker.min.js?url'
import type { ElkNode } from 'elkjs/lib/elk-api.js'
import type { TopologyLayoutRequest, TopologyLayoutResponse } from './topology-layout-protocol'

type ElkLayoutEngine = {
  layout: (graph: ElkNode) => Promise<ElkNode>
}

let elk: ElkLayoutEngine | null = null
let cachedLayout: { key: string; promise: Promise<Array<{ id: string; x: number; y: number }>> } | null = null

function getElk(): ElkLayoutEngine {
  elk ??= new ELK({ workerUrl: elkWorkerUrl })
  return elk
}

export async function layoutTopology(request: TopologyLayoutRequest): Promise<TopologyLayoutResponse> {
  const cacheKey = JSON.stringify({
    revision: request.revision,
    direction: request.direction,
    nodes: request.nodes,
    edges: request.edges,
  })
  try {
    const graph: ElkNode = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': request.direction,
        'elk.edgeRouting': 'ORTHOGONAL',
        'elk.spacing.nodeNode': '58',
        'elk.layered.spacing.nodeNodeBetweenLayers': '118',
        'elk.layered.spacing.edgeNodeBetweenLayers': '42',
        'elk.layered.thoroughness': request.nodes.length > 200 ? '3' : '7',
        'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
        'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
        'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
        'elk.padding': '[top=48,left=48,bottom=48,right=48]',
      },
      children: request.nodes.map((node) => ({
        id: node.id,
        width: node.width,
        height: node.height,
        layoutOptions: node.kind === 'segment'
          ? { 'elk.layered.layering.layerConstraint': 'FIRST' }
          : node.kind === 'device'
            ? { 'elk.layered.layering.layerConstraint': 'LAST' }
            : undefined,
      })),
      edges: request.edges.map((edge) => ({
        id: edge.id,
        sources: [edge.source],
        targets: [edge.target],
      })),
    }
    if (cachedLayout?.key !== cacheKey) {
      cachedLayout = {
        key: cacheKey,
        promise: getElk().layout(graph).then((layout) => (layout.children ?? []).map((node) => ({
          id: node.id,
          x: node.x ?? 0,
          y: node.y ?? 0,
        }))),
      }
    }
    const positions = await cachedLayout.promise
    return {
      requestId: request.requestId,
      ok: true,
      positions,
    }
  } catch (error) {
    if (cachedLayout?.key === cacheKey) {
      cachedLayout = null
    }
    return {
      requestId: request.requestId,
      ok: false,
      error: error instanceof Error ? error.message : 'Topology layout failed',
    }
  }
}
