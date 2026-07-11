import { type ReactNode, useEffect, useId, useRef, useState } from 'react'
import { X } from 'lucide-react'

type DraggableModalProps = {
  label: string
  title: string
  meta?: ReactNode
  widthClassName?: string
  children: ReactNode
  onClose: () => void
}

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

export default function DraggableModal({ label, title, meta, widthClassName, children, onClose }: DraggableModalProps) {
  const [position, setPosition] = useState<{ x: number; y: number } | null>(null)
  const dragState = useRef<{ offsetX: number; offsetY: number } | null>(null)
  const panelRef = useRef<HTMLElement | null>(null)
  const onCloseRef = useRef(onClose)
  const titleId = useId()
  onCloseRef.current = onClose

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const panel = panelRef.current
    const initialFocus = panel?.querySelector<HTMLElement>(focusableSelector) ?? panel
    initialFocus?.focus()

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onCloseRef.current()
        return
      }
      if (event.key !== 'Tab' || !panelRef.current) {
        return
      }

      const focusable = [...panelRef.current.querySelectorAll<HTMLElement>(focusableSelector)].filter(
        (element) => element.getClientRects().length > 0,
      )
      if (focusable.length === 0) {
        event.preventDefault()
        panelRef.current.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = previousOverflow
      previouslyFocused?.focus()
    }
  }, [])

  useEffect(() => {
    const handleMouseMove = (event: MouseEvent) => {
      if (!dragState.current || !panelRef.current) {
        return
      }

      const rect = panelRef.current.getBoundingClientRect()
      const maxX = Math.max(8, window.innerWidth - rect.width - 8)
      const maxY = Math.max(8, window.innerHeight - rect.height - 8)
      setPosition({
        x: Math.min(Math.max(8, event.clientX - dragState.current.offsetX), maxX),
        y: Math.min(Math.max(8, event.clientY - dragState.current.offsetY), maxY),
      })
    }

    const stopDragging = () => {
      dragState.current = null
    }

    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseup', stopDragging)

    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseup', stopDragging)
    }
  }, [])

  const className = widthClassName ? `modal-panel ${widthClassName}` : 'modal-panel'

  return (
    <div
      className="modal-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose()
        }
      }}
    >
      <section
        ref={panelRef}
        className={className}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={
          position
            ? {
                left: `${position.x}px`,
                top: `${position.y}px`,
                transform: 'none',
              }
            : undefined
        }
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div
          className="modal-panel__header"
          onMouseDown={(event) => {
            const target = event.target as HTMLElement
            if (target.closest('button, input, textarea, select, a')) {
              return
            }

            const panel = panelRef.current
            if (!panel) {
              return
            }

            const rect = panel.getBoundingClientRect()
            dragState.current = {
              offsetX: event.clientX - rect.left,
              offsetY: event.clientY - rect.top,
            }

            setPosition({ x: rect.left, y: rect.top })
          }}
        >
          <div className="modal-panel__title-group">
            <p className="section-label">{label}</p>
            <h2 id={titleId}>{title}</h2>
            {meta ? <div className="modal-panel__meta">{meta}</div> : null}
          </div>
          <button
            type="button"
            className="icon-danger-button"
            onClick={onClose}
            aria-label={`Close ${title}`}
            title={`Close ${title}`}
          >
            <X aria-hidden="true" />
          </button>
        </div>
        {children}
      </section>
    </div>
  )
}
