const rainColumns = Array.from({ length: 26 }, (_, index) => ({
  id: index,
  left: `${(index * 4) % 100}%`,
  delay: `${(index % 9) * -0.7}s`,
  duration: `${8 + (index % 7)}s`,
  text: index % 2 === 0 ? "0100110011010110" : "1101001010010111",
}));

const packets = Array.from({ length: 18 }, (_, index) => ({
  id: index,
  left: `${(index * 13) % 100}%`,
  top: `${(index * 29) % 100}%`,
  delay: `${(index % 6) * -0.8}s`,
}));

export function CyberBackdrop() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-[#020404]">
      <div className="absolute inset-0 cyber-grid" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_25%_10%,rgba(0,255,179,0.14),transparent_32%),radial-gradient(circle_at_80%_18%,rgba(0,194,255,0.12),transparent_30%),linear-gradient(135deg,rgba(4,12,12,0.98),rgba(2,4,6,0.94)_48%,rgba(5,14,17,0.98))]" />
      <div className="absolute inset-0 opacity-40">
        {rainColumns.map((column) => (
          <span
            aria-hidden="true"
            className="matrix-rain absolute top-[-35%] w-4 break-all font-mono text-[11px] leading-4 text-emerald-300/35"
            key={column.id}
            style={{
              left: column.left,
              animationDelay: column.delay,
              animationDuration: column.duration,
            }}
          >
            {column.text.repeat(8)}
          </span>
        ))}
      </div>
      <div className="absolute inset-0">
        {packets.map((packet) => (
          <span
            aria-hidden="true"
            className="data-packet absolute h-1.5 w-1.5 rounded-sm bg-cyan-300/70 shadow-[0_0_20px_rgba(34,211,238,0.55)]"
            key={packet.id}
            style={{
              left: packet.left,
              top: packet.top,
              animationDelay: packet.delay,
            }}
          />
        ))}
      </div>
      <div className="scanline absolute inset-x-0 top-0 h-32 bg-gradient-to-b from-transparent via-cyan-200/10 to-transparent" />
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.025)_1px,transparent_1px)] bg-[length:100%_4px] opacity-30" />
      <div className="absolute inset-0 shadow-[inset_0_0_160px_rgba(0,0,0,0.9)]" />
    </div>
  );
}
