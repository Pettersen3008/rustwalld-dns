import { Component, Suspense, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { lines, pretty } from "@/lib/api";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { AlertCircle, LoaderCircle } from "lucide-react";
import { errorMessage } from "@/lib/api";
export class DeferredView extends Component<{ children: ReactNode }, { error: unknown }> {
  state: { error: unknown } = { error: null };
  static getDerivedStateFromError(error: unknown) {
    return { error };
  }
  render() {
    if (this.state.error)
      return (
        <section>
          <ErrorNotice error={this.state.error} />
          <p className="body-copy">
            This view could not load. You can use the other views, or refresh the browser and
            reconnect. Refreshing discards any unsaved draft in this tab.
          </p>
        </section>
      );
    return <Suspense fallback={<Loading />}>{this.props.children}</Suspense>;
  }
}
export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "green" | "amber" | "red";
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  if (!error) return null;
  return (
    <div className="notice notice-error" role="alert">
      <AlertCircle size={18} />
      <div>{errorMessage(error)}</div>
      {retry && <button onClick={retry}>Retry</button>}
    </div>
  );
}
export function Loading() {
  return (
    <div className="empty">
      <LoaderCircle className="spin" size={22} /> Loading live data…
    </div>
  );
}
export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
export function Panel({
  title,
  detail,
  children,
  action,
}: {
  title: string;
  detail?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {detail && <p>{detail}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
export function Modal({
  open,
  onClose,
  title,
  description,
  returnFocus,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  returnFocus?: HTMLElement | null;
  children: ReactNode;
}) {
  const focus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (open && document.activeElement instanceof HTMLElement)
      focus.current = document.activeElement;
  }, [open]);
  return (
    <Dialog
      open={open}
      onOpenChange={(value) => {
        if (!value) onClose();
      }}
    >
      <DialogContent
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          const origin = returnFocus ?? focus.current;
          if (
            origin?.isConnected &&
            origin !== document.body &&
            !origin.matches(":disabled") &&
            !origin.closest("[inert]")
          ) {
            origin.focus();
            if (document.activeElement === origin) return;
          }
          document.getElementById("main-content")?.focus();
        }}
      >
        <div className="dialog-head">
          <div>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </div>
        </div>
        {children}
      </DialogContent>
    </Dialog>
  );
}

// Preserve separators while editing; the compiler receives normalized arrays.
export function TextList({
  values,
  commit,
  multiline = false,
  rows = 3,
}: {
  values: string[];
  commit: (values: string[]) => void;
  multiline?: boolean;
  rows?: number;
}) {
  const separator = multiline ? "\n" : ", ";
  const [raw, setRaw] = useState(values.join(separator));
  if (pretty(lines(raw)) !== pretty(values)) setRaw(values.join(separator));
  const props = {
    value: raw,
    className: "mono",
    onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      const value = event.target.value;
      setRaw(value);
      commit(lines(value));
    },
  };
  return multiline ? <textarea {...props} rows={rows} /> : <input {...props} />;
}
