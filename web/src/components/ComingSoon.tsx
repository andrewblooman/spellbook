export function ComingSoon({ title, note }: { title: string; note?: string }) {
  return (
    <>
      <div className="pagehead">
        <span className="eyebrow">Spellbook</span>
        <h2>{title}</h2>
      </div>
      <div className="empty">
        <div style={{ fontSize: 34, marginBottom: 10 }}>🚧</div>
        {note ?? "This chamber is still being conjured. Check back soon."}
      </div>
    </>
  );
}
