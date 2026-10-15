export type Section =
  | "rules"
  | "networks"
  | "upstreams"
  | "assertions"
  | "exceptions"
  | "sources"
  | "local-dns"
  | "services"
  | "safe-search"
  | "migration";
export const sections: readonly Section[] = [
  "rules",
  "networks",
  "upstreams",
  "assertions",
  "exceptions",
  "sources",
  "local-dns",
  "services",
  "safe-search",
  "migration",
];

export function EditorSections({
  section,
  select,
}: {
  section: Section;
  select: (value: Section) => void;
}) {
  return (
    <div className="tabs" role="tablist" aria-label="Policy editor sections">
      {sections.map((id) => (
        <button
          role="tab"
          aria-selected={section === id}
          aria-controls={`editor-${id}`}
          tabIndex={section === id ? 0 : -1}
          id={`tab-${id}`}
          key={id}
          onClick={() => select(id)}
          onKeyDown={(event) => {
            const index = sections.indexOf(id);
            const next =
              event.key === "ArrowRight"
                ? (index + 1) % sections.length
                : event.key === "ArrowLeft"
                  ? (index + sections.length - 1) % sections.length
                  : event.key === "Home"
                    ? 0
                    : event.key === "End"
                      ? sections.length - 1
                      : null;
            if (next === null) return;
            event.preventDefault();
            const destination = sections[next]!;
            select(destination);
            document.getElementById(`tab-${destination}`)?.focus();
          }}
        >
          {id === "rules"
            ? "Policies & rules"
            : id === "networks"
              ? "Clients & networks"
              : id === "upstreams"
                ? "Upstream profiles"
                : id === "assertions"
                  ? "Assertions"
                  : id === "exceptions"
                    ? "Temporary exceptions"
                    : id === "sources"
                      ? "Downloaded lists"
                      : id === "local-dns"
                        ? "Local DNS & routes"
                        : id === "services"
                          ? "Services"
                          : id === "safe-search"
                            ? "SafeSearch"
                            : "Migration"}
        </button>
      ))}
    </div>
  );
}
