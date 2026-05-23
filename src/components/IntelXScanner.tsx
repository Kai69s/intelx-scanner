"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  Bell,
  Command,
  Cpu,
  DatabaseZap,
  Download,
  Eraser,
  Eye,
  FileDown,
  Fingerprint,
  Gauge,
  History,
  Loader2,
  LockKeyhole,
  Network,
  Radar,
  Radio,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Volume2,
  VolumeX,
  Zap,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ThreatMeter } from "@/components/ThreatMeter";
import type { IntelligenceReport, ScanErrorResponse, ScanResponse } from "@/lib/types";

const scanStages = [
  "Initializing Intel Scan",
  "Resolving identity graph",
  "Parsing breach records",
  "Correlating indexed services",
  "Decrypting intelligence",
  "Threat Analysis Complete",
];

const ambientLogSeeds = [
  "RX module handshake accepted",
  "Passive DNS shard synchronized",
  "Credential hash index warmed",
  "Leak archive cursor advanced",
  "Telemetry relay sealed",
  "Breach corpus delta indexed",
  "Signal entropy within tolerance",
  "Watchlist pulse acknowledged",
];

const navItems = [
  { label: "Scanner", icon: Radar },
  { label: "Intelligence", icon: Fingerprint },
  { label: "Activity", icon: Activity },
  { label: "Archive", icon: DatabaseZap },
];

type HistoryItem = Pick<
  IntelligenceReport,
  "email" | "scannedAt" | "riskLevel" | "totalMatches" | "status"
>;

type CachedReport = {
  report: IntelligenceReport;
  expiresAt: number;
};

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function classNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    year: "numeric",
  }).format(new Date(value));
}

function severityClass(level: IntelligenceReport["riskLevel"]) {
  return {
    clear: "border-emerald-300/30 bg-emerald-300/10 text-emerald-100",
    guarded: "border-cyan-300/30 bg-cyan-300/10 text-cyan-100",
    elevated: "border-amber-300/30 bg-amber-300/10 text-amber-100",
    high: "border-orange-300/30 bg-orange-300/10 text-orange-100",
    critical: "border-red-300/30 bg-red-300/10 text-red-100",
  }[level];
}

function StatCard({
  label,
  value,
  detail,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Activity;
  tone: string;
}) {
  return (
    <motion.div
      className="panel min-h-[136px] p-5"
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      viewport={{ once: true }}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase text-slate-400">{label}</p>
          <p className="mt-3 text-3xl font-semibold text-white">{value}</p>
        </div>
        <span className={classNames("grid h-10 w-10 place-items-center rounded-md border", tone)}>
          <Icon aria-hidden="true" className="h-5 w-5" />
        </span>
      </div>
      <p className="mt-4 text-sm leading-6 text-slate-400">{detail}</p>
    </motion.div>
  );
}

function MiniTrafficChart() {
  const bars = [42, 68, 54, 81, 62, 92, 74, 46, 88, 58, 70, 96];

  return (
    <div className="panel p-5">
      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase text-slate-400">Traffic graph</p>
          <h2 className="mt-1 text-lg font-semibold text-white">Index throughput</h2>
        </div>
        <span className="rounded-md border border-emerald-300/25 bg-emerald-300/10 px-3 py-1 font-mono text-xs text-emerald-200">
          LIVE
        </span>
      </div>
      <div className="flex h-32 items-end gap-2">
        {bars.map((height, index) => (
          <motion.span
            animate={{ height: [`${height - 18}%`, `${height}%`, `${height - 8}%`] }}
            className="w-full rounded-sm bg-gradient-to-t from-cyan-400/25 to-emerald-300 shadow-[0_0_18px_rgba(45,212,191,0.16)]"
            key={index}
            transition={{
              duration: 2.4 + index * 0.08,
              repeat: Infinity,
              repeatType: "mirror",
              ease: "easeInOut",
            }}
          />
        ))}
      </div>
    </div>
  );
}

function NodeMap() {
  const nodes = [
    { x: 28, y: 32 },
    { x: 48, y: 20 },
    { x: 70, y: 34 },
    { x: 38, y: 62 },
    { x: 62, y: 70 },
  ];

  return (
    <div className="panel relative min-h-[250px] overflow-hidden p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase text-slate-400">Signal mesh</p>
          <h2 className="mt-1 text-lg font-semibold text-white">Global exposure graph</h2>
        </div>
        <Network aria-hidden="true" className="h-5 w-5 text-cyan-200" />
      </div>
      <svg aria-hidden="true" className="absolute inset-x-4 bottom-3 top-16 h-[170px] w-[calc(100%-2rem)]">
        <defs>
          <linearGradient id="line" x1="0" x2="1" y1="0" y2="1">
            <stop stopColor="#22d3ee" stopOpacity="0.15" />
            <stop offset="1" stopColor="#34d399" stopOpacity="0.65" />
          </linearGradient>
        </defs>
        <path
          d="M80 62 C140 8 210 28 270 78 S380 132 455 92"
          fill="none"
          stroke="url(#line)"
          strokeWidth="2"
        />
        <path
          d="M130 132 C200 88 250 128 320 146 S418 118 475 150"
          fill="none"
          stroke="url(#line)"
          strokeWidth="2"
        />
        {nodes.map((node, index) => (
          <motion.circle
            animate={{ r: [5, 8, 5], opacity: [0.55, 1, 0.55] }}
            cx={`${node.x}%`}
            cy={`${node.y}%`}
            fill={index % 2 ? "#22d3ee" : "#34d399"}
            key={`${node.x}-${node.y}`}
            transition={{ duration: 2.2, repeat: Infinity, delay: index * 0.24 }}
          />
        ))}
      </svg>
      <div className="absolute bottom-5 left-5 right-5 grid grid-cols-3 gap-2 text-xs text-slate-400">
        <span>NA: 42ms</span>
        <span>EU: 58ms</span>
        <span>APAC: 73ms</span>
      </div>
    </div>
  );
}

function CommandPalette({
  open,
  onClose,
  onScan,
  onExport,
  onClear,
  onSoundToggle,
}: {
  open: boolean;
  onClose: () => void;
  onScan: () => void;
  onExport: () => void;
  onClear: () => void;
  onSoundToggle: () => void;
}) {
  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          animate={{ opacity: 1 }}
          className="fixed inset-0 z-50 grid place-items-start bg-black/70 px-4 pt-24 backdrop-blur-xl sm:place-items-center sm:pt-0"
          exit={{ opacity: 0 }}
          initial={{ opacity: 0 }}
          role="dialog"
          aria-modal="true"
        >
          <motion.div
            animate={{ opacity: 1, scale: 1, y: 0 }}
            className="w-full max-w-lg rounded-lg border border-cyan-300/20 bg-[#061011]/95 p-3 shadow-[0_0_50px_rgba(34,211,238,0.2)]"
            exit={{ opacity: 0, scale: 0.98, y: 12 }}
            initial={{ opacity: 0, scale: 0.98, y: 12 }}
          >
            <div className="flex items-center gap-3 border-b border-white/10 px-3 py-3">
              <Command aria-hidden="true" className="h-5 w-5 text-cyan-200" />
              <p className="font-mono text-sm text-slate-200">Command deck</p>
              <button
                aria-label="Close command deck"
                className="ml-auto rounded-md border border-white/10 px-2 py-1 text-xs text-slate-400 hover:border-cyan-300/40 hover:text-cyan-100"
                onClick={onClose}
                type="button"
              >
                Close
              </button>
            </div>
            <div className="mt-3 grid gap-2">
              {[
                { label: "Run active scan", icon: ScanLine, action: onScan },
                { label: "Export report PDF", icon: FileDown, action: onExport },
                { label: "Clear local history", icon: Eraser, action: onClear },
                { label: "Toggle scan audio", icon: Volume2, action: onSoundToggle },
              ].map((item) => (
                <button
                  className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.03] px-4 py-3 text-left text-sm text-slate-200 transition hover:border-emerald-300/40 hover:bg-emerald-300/10"
                  key={item.label}
                  onClick={() => {
                    item.action();
                    onClose();
                  }}
                  type="button"
                >
                  <item.icon aria-hidden="true" className="h-4 w-4 text-emerald-200" />
                  {item.label}
                </button>
              ))}
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

export function IntelXScanner() {
  const [email, setEmail] = useState("");
  const [report, setReport] = useState<IntelligenceReport | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [accent, setAccent] = useState<"emerald" | "cyan">("emerald");
  const cacheRef = useRef(new Map<string, CachedReport>());
  const inputRef = useRef<HTMLInputElement>(null);

  const visibleStage = scanStages[Math.min(stageIndex, scanStages.length - 1)];

  const systemStats = useMemo(
    () => [
      { label: "Corpus sync", value: "99.98%", icon: Cpu },
      { label: "Relay state", value: "SEALED", icon: LockKeyhole },
      { label: "Signals", value: "18.4K", icon: Radio },
    ],
    [],
  );

  const pushLog = useCallback((message: string) => {
    const stamp = new Intl.DateTimeFormat("en", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date());

    setLogs((current) => [`${stamp}  ${message}`, ...current].slice(0, 12));
  }, []);

  const playTone = useCallback(() => {
    if (!soundEnabled || typeof window === "undefined") return;

    const audioWindow = window as Window &
      typeof globalThis & {
        webkitAudioContext?: typeof AudioContext;
      };
    const AudioContextClass = audioWindow.AudioContext || audioWindow.webkitAudioContext;
    if (!AudioContextClass) return;

    const context = new AudioContextClass();
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(880, context.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(220, context.currentTime + 0.16);
    gain.gain.setValueAtTime(0.04, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.18);
    oscillator.connect(gain);
    gain.connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.18);
  }, [soundEnabled]);

  const saveReport = useCallback((nextReport: IntelligenceReport) => {
    setReport(nextReport);
    setHistory((current) => {
      const next = [
        {
          email: nextReport.email,
          scannedAt: nextReport.scannedAt,
          riskLevel: nextReport.riskLevel,
          totalMatches: nextReport.totalMatches,
          status: nextReport.status,
        },
        ...current.filter((item) => item.email !== nextReport.email),
      ].slice(0, 8);
      localStorage.setItem("intelx-history", JSON.stringify(next));
      return next;
    });
  }, []);

  const exportPdf = useCallback(async () => {
    if (!report) {
      pushLog("Export rejected: no active report");
      return;
    }

    const { jsPDF } = await import("jspdf");
    const pdf = new jsPDF();
    const lines = [
      "IntelX Scanner Intelligence Report",
      `Email: ${report.email}`,
      `Scanned: ${new Date(report.scannedAt).toLocaleString()}`,
      `Risk: ${report.riskLevel.toUpperCase()}`,
      `Status: ${report.breachStatus}`,
      `Total matches: ${report.totalMatches}`,
      `Breaches: ${report.breachCount}`,
      `Leaks: ${report.leakCount}`,
      "",
      "Summary",
      report.summary,
      "",
      "Platforms",
      report.platforms.length ? report.platforms.join(", ") : "None returned",
      "",
      "Usernames",
      report.usernames.length ? report.usernames.join(", ") : "None returned",
    ];

    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(16);
    pdf.text(lines[0], 14, 18);
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(10);

    let y = 32;
    for (const line of lines.slice(1)) {
      const wrapped = pdf.splitTextToSize(line, 180) as string[];
      for (const segment of wrapped) {
        if (y > 280) {
          pdf.addPage();
          y = 18;
        }
        pdf.text(segment, 14, y);
        y += 7;
      }
    }

    pdf.save(`intelx-${report.email.replace(/[^a-z0-9]/gi, "_")}.pdf`);
    pushLog("PDF report exported");
  }, [pushLog, report]);

  const runScan = useCallback(async () => {
    const normalizedEmail = email.trim().toLowerCase();
    setError(null);

    if (!emailPattern.test(normalizedEmail)) {
      setError("Enter a valid email address to initialize the scan.");
      pushLog("Scan rejected: invalid identity format");
      return;
    }

    const cached = cacheRef.current.get(normalizedEmail);
    if (cached && cached.expiresAt > Date.now()) {
      pushLog("Local cache hit: report replayed");
      saveReport(cached.report);
      return;
    }

    setIsScanning(true);
    setStageIndex(0);
    setReport(null);
    pushLog(`Scan initialized for ${normalizedEmail}`);
    playTone();

    const stageTimer = window.setInterval(() => {
      setStageIndex((current) => Math.min(current + 1, scanStages.length - 2));
    }, 640);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: normalizedEmail }),
      });

      const body = (await response.json()) as ScanResponse | ScanErrorResponse;

      if (!response.ok || "error" in body) {
        throw new Error("error" in body ? body.error : "Scan relay failed.");
      }

      window.clearInterval(stageTimer);
      setStageIndex(scanStages.length - 1);

      await new Promise((resolve) => window.setTimeout(resolve, 480));
      cacheRef.current.set(normalizedEmail, {
        report: body.report,
        expiresAt: Date.now() + 1000 * 60 * 5,
      });
      saveReport(body.report);
      pushLog(body.report.status === "detected" ? "Threat signature detected" : "No exposure detected");
      playTone();
    } catch (scanError) {
      window.clearInterval(stageTimer);
      const message = scanError instanceof Error ? scanError.message : "Scan failed.";
      setError(message);
      setStageIndex(0);
      pushLog("Scan relay returned a controlled fault");
    } finally {
      setIsScanning(false);
    }
  }, [email, playTone, pushLog, saveReport]);

  const clearHistory = useCallback(() => {
    localStorage.removeItem("intelx-history");
    setHistory([]);
    pushLog("Local investigation history cleared");
  }, [pushLog]);

  useEffect(() => {
    const hydrationTimer = window.setTimeout(() => {
      const storedHistory = localStorage.getItem("intelx-history");
      if (storedHistory) {
        try {
          setHistory(JSON.parse(storedHistory) as HistoryItem[]);
        } catch {
          localStorage.removeItem("intelx-history");
        }
      }

      setLogs(
        ambientLogSeeds.slice(0, 6).map((message, index) => {
          const stamp = new Intl.DateTimeFormat("en", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }).format(new Date(Date.now() - index * 12000));
          return `${stamp}  ${message}`;
        }),
      );
    }, 0);

    return () => window.clearTimeout(hydrationTimer);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const message = ambientLogSeeds[Math.floor(Math.random() * ambientLogSeeds.length)];
      pushLog(message);
    }, 3600);

    return () => window.clearInterval(timer);
  }, [pushLog]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const isTyping =
        target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable;

      if (event.key === "/" && !isTyping) {
        event.preventDefault();
        inputRef.current?.focus();
      }

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      }

      if (event.key === "Escape") {
        setCommandOpen(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void runScan();
  };

  return (
    <main className={classNames("min-h-screen text-slate-100", accent === "cyan" && "accent-cyan")}>
      <CommandPalette
        onClear={clearHistory}
        onClose={() => setCommandOpen(false)}
        onExport={exportPdf}
        onScan={() => void runScan()}
        onSoundToggle={() => setSoundEnabled((value) => !value)}
        open={commandOpen}
      />

      <div className="mx-auto flex w-full max-w-[1800px] flex-col gap-4 px-4 py-4 lg:flex-row lg:px-6">
        <aside className="panel lg:sticky lg:top-4 lg:h-[calc(100vh-2rem)] lg:w-[270px] lg:shrink-0">
          <div className="flex items-center gap-3 border-b border-white/10 p-4">
            <div className="grid h-11 w-11 place-items-center rounded-md border border-emerald-300/30 bg-emerald-300/10 shadow-[0_0_28px_rgba(52,211,153,0.22)]">
              <Eye aria-hidden="true" className="h-5 w-5 text-emerald-200" />
            </div>
            <div>
              <p className="font-mono text-xs uppercase text-emerald-200">IntelX Scanner</p>
              <h1 className="text-lg font-semibold text-white">OSINT Console</h1>
            </div>
          </div>

          <nav className="grid gap-2 p-3" aria-label="Primary">
            {navItems.map((item, index) => (
              <button
                className={classNames(
                  "flex items-center gap-3 rounded-md border px-3 py-3 text-left text-sm transition",
                  index === 0
                    ? "border-emerald-300/30 bg-emerald-300/10 text-emerald-100"
                    : "border-transparent text-slate-400 hover:border-cyan-300/30 hover:bg-cyan-300/10 hover:text-cyan-100",
                )}
                key={item.label}
                type="button"
              >
                <item.icon aria-hidden="true" className="h-4 w-4" />
                {item.label}
              </button>
            ))}
          </nav>

          <div className="p-4">
            <div className="rounded-lg border border-white/10 bg-black/20 p-4">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-xs uppercase text-slate-400">System stats</p>
                <span className="h-2 w-2 rounded-sm bg-emerald-300 shadow-[0_0_16px_rgba(52,211,153,0.9)]" />
              </div>
              <div className="grid gap-3">
                {systemStats.map((stat) => (
                  <div className="flex items-center justify-between gap-3" key={stat.label}>
                    <span className="flex items-center gap-2 text-sm text-slate-400">
                      <stat.icon aria-hidden="true" className="h-4 w-4 text-cyan-200" />
                      {stat.label}
                    </span>
                    <span className="font-mono text-sm text-slate-100">{stat.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-auto border-t border-white/10 p-4">
            <div className="flex items-center gap-2 text-xs uppercase text-slate-400">
              <ShieldCheck aria-hidden="true" className="h-4 w-4 text-emerald-200" />
              Server key isolated
            </div>
          </div>
        </aside>

        <section className="flex min-w-0 flex-1 flex-col gap-4">
          <header className="panel flex flex-col gap-4 p-4 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="font-mono text-xs uppercase text-cyan-200">Breach intelligence relay</p>
              <h2 className="mt-1 text-2xl font-semibold text-white md:text-3xl">Email exposure scanner</h2>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                aria-label="Toggle audio"
                className="icon-button"
                onClick={() => setSoundEnabled((value) => !value)}
                title="Toggle audio"
                type="button"
              >
                {soundEnabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
              </button>
              <button
                aria-label="Switch accent"
                className="icon-button"
                onClick={() => setAccent((value) => (value === "emerald" ? "cyan" : "emerald"))}
                title="Switch accent"
                type="button"
              >
                <Sparkles className="h-4 w-4" />
              </button>
              <button
                aria-label="Open command deck"
                className="icon-button"
                onClick={() => setCommandOpen(true)}
                title="Open command deck"
                type="button"
              >
                <Command className="h-4 w-4" />
              </button>
            </div>
          </header>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_390px]">
            <div className="flex min-w-0 flex-col gap-4">
              <motion.form
                animate={{ opacity: 1, y: 0 }}
                className="panel overflow-hidden"
                initial={{ opacity: 0, y: 16 }}
                onSubmit={handleSubmit}
              >
                <div className="border-b border-white/10 p-5">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
                    <label className="min-w-0 flex-1">
                      <span className="mb-2 block text-xs uppercase text-slate-400">Target identity</span>
                      <span className="flex min-h-14 items-center gap-3 rounded-lg border border-cyan-300/20 bg-black/40 px-4 shadow-[inset_0_0_22px_rgba(34,211,238,0.06)] focus-within:border-emerald-300/50">
                        <Search aria-hidden="true" className="h-5 w-5 shrink-0 text-cyan-200" />
                        <input
                          autoComplete="email"
                          className="min-w-0 flex-1 bg-transparent py-4 font-mono text-base text-white outline-none placeholder:text-slate-600"
                          disabled={isScanning}
                          onChange={(event) => setEmail(event.target.value)}
                          placeholder="analyst@example.com"
                          ref={inputRef}
                          type="email"
                          value={email}
                        />
                      </span>
                    </label>
                    <button
                      className="glow-button min-h-14 px-5"
                      disabled={isScanning}
                      type="submit"
                    >
                      {isScanning ? (
                        <Loader2 aria-hidden="true" className="h-5 w-5 animate-spin" />
                      ) : (
                        <ScanLine aria-hidden="true" className="h-5 w-5" />
                      )}
                      {isScanning ? "Scanning" : "Initialize scan"}
                    </button>
                  </div>
                  {error ? (
                    <motion.p
                      animate={{ opacity: 1 }}
                      className="mt-3 rounded-md border border-red-300/25 bg-red-400/10 px-3 py-2 text-sm text-red-100"
                      initial={{ opacity: 0 }}
                      role="alert"
                    >
                      {error}
                    </motion.p>
                  ) : null}
                </div>

                <div className="grid gap-4 p-5 lg:grid-cols-[1fr_280px]">
                  <div>
                    <div className="mb-4 flex items-center justify-between gap-4">
                      <p className="text-xs uppercase text-slate-400">Scan sequence</p>
                      <p className="font-mono text-xs text-cyan-200" aria-live="polite">
                        {visibleStage}
                      </p>
                    </div>
                    <div className="grid gap-3">
                      {scanStages.map((stage, index) => (
                        <div className="flex items-center gap-3" key={stage}>
                          <span
                            className={classNames(
                              "grid h-7 w-7 shrink-0 place-items-center rounded-md border font-mono text-xs",
                              index <= stageIndex || (!isScanning && report && index === scanStages.length - 1)
                                ? "border-emerald-300/40 bg-emerald-300/10 text-emerald-100"
                                : "border-white/10 bg-white/[0.03] text-slate-500",
                            )}
                          >
                            {index + 1}
                          </span>
                          <div className="h-px flex-1 bg-white/10" />
                          <span
                            className={classNames(
                              "w-52 text-sm",
                              index <= stageIndex ? "text-slate-100" : "text-slate-500",
                            )}
                          >
                            {stage}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="relative min-h-[180px] overflow-hidden rounded-lg border border-cyan-300/15 bg-black/35 p-4">
                    <div className="absolute inset-0 diagnostic-sweep" />
                    <div className="relative flex h-full flex-col justify-between">
                      <div>
                        <p className="text-xs uppercase text-slate-400">Packet stream</p>
                        <p className="mt-2 font-mono text-3xl text-cyan-100">
                          {isScanning ? "ACTIVE" : report ? "SEALED" : "READY"}
                        </p>
                      </div>
                      <div className="grid grid-cols-3 gap-2 font-mono text-xs text-slate-400">
                        <span>IDX 7A</span>
                        <span>CRC OK</span>
                        <span>TTL 12</span>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.form>

              <AnimatePresence mode="wait">
                {report ? (
                  <motion.section
                    animate={{ opacity: 1, y: 0 }}
                    className="grid gap-4"
                    exit={{ opacity: 0, y: 12 }}
                    initial={{ opacity: 0, y: 18 }}
                    key={report.scannedAt}
                  >
                    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                      <StatCard
                        detail="Correlated records returned by the Intelbase relay."
                        icon={DatabaseZap}
                        label="Total matches"
                        tone="border-cyan-300/30 bg-cyan-300/10 text-cyan-100"
                        value={String(report.totalMatches)}
                      />
                      <StatCard
                        detail="Known breach-adjacent records observed in the response."
                        icon={ShieldAlert}
                        label="Breach records"
                        tone="border-red-300/30 bg-red-300/10 text-red-100"
                        value={String(report.breachCount)}
                      />
                      <StatCard
                        detail="Leak, paste, or database style exposure signals."
                        icon={Zap}
                        label="Leak signals"
                        tone="border-amber-300/30 bg-amber-300/10 text-amber-100"
                        value={String(report.leakCount)}
                      />
                      <StatCard
                        detail="Indexed platforms, modules, or source names extracted."
                        icon={Network}
                        label="Platforms"
                        tone="border-emerald-300/30 bg-emerald-300/10 text-emerald-100"
                        value={String(report.platforms.length)}
                      />
                    </div>

                    <div className="grid gap-4 xl:grid-cols-[330px_1fr]">
                      <ThreatMeter level={report.riskLevel} />
                      <div className="panel p-5">
                        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <p className="text-xs uppercase text-slate-400">Intelligence summary</p>
                            <h2 className="mt-1 text-xl font-semibold text-white">{report.breachStatus}</h2>
                          </div>
                          <span className={classNames("rounded-md border px-3 py-1 text-xs uppercase", severityClass(report.riskLevel))}>
                            {report.riskLevel}
                          </span>
                        </div>
                        <p className="max-w-4xl text-sm leading-7 text-slate-300">{report.summary}</p>
                        <div className="mt-5 grid gap-3 font-mono text-xs text-slate-400 md:grid-cols-3">
                          <span>Target: {report.email}</span>
                          <span>Scanned: {formatTime(report.scannedAt)}</span>
                          <span>Latency: {report.durationMs}ms</span>
                        </div>
                      </div>
                    </div>

                    <div className="grid gap-4 xl:grid-cols-2">
                      <div className="panel p-5">
                        <div className="mb-4 flex items-center justify-between gap-4">
                          <div>
                            <p className="text-xs uppercase text-slate-400">Source matrix</p>
                            <h2 className="mt-1 text-lg font-semibold text-white">Indexed records</h2>
                          </div>
                          <button
                            aria-label="Export report PDF"
                            className="icon-button"
                            onClick={exportPdf}
                            title="Export report PDF"
                            type="button"
                          >
                            <Download className="h-4 w-4" />
                          </button>
                        </div>
                        <div className="grid gap-3">
                          {report.sources.length ? (
                            report.sources.map((source) => (
                              <div
                                className="rounded-lg border border-white/10 bg-white/[0.03] p-4"
                                key={`${source.category}-${source.name}`}
                              >
                                <div className="flex items-start justify-between gap-3">
                                  <div>
                                    <p className="font-medium text-slate-100">{source.name}</p>
                                    <p className="mt-1 text-xs uppercase text-slate-500">{source.category}</p>
                                  </div>
                                  <span className="font-mono text-sm text-cyan-200">
                                    {source.count ?? 1}
                                  </span>
                                </div>
                                {source.lastSeen ? (
                                  <p className="mt-3 text-xs text-slate-500">
                                    Last signal {formatDate(source.lastSeen)}
                                  </p>
                                ) : null}
                              </div>
                            ))
                          ) : (
                            <p className="rounded-lg border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                              No named source modules were returned for this identity.
                            </p>
                          )}
                        </div>
                      </div>

                      <div className="panel p-5">
                        <p className="text-xs uppercase text-slate-400">Entity extraction</p>
                        <h2 className="mt-1 text-lg font-semibold text-white">Associated signals</h2>
                        <div className="mt-5 grid gap-5">
                          {[
                            { label: "Usernames", values: report.usernames },
                            { label: "Domains", values: report.domains },
                            { label: "Platforms", values: report.platforms },
                            {
                              label: "Timestamps",
                              values: report.timestamps.map((timestamp) => formatDate(timestamp)),
                            },
                          ].map((group) => (
                            <div key={group.label}>
                              <p className="mb-2 text-xs uppercase text-slate-500">{group.label}</p>
                              <div className="flex flex-wrap gap-2">
                                {group.values.length ? (
                                  group.values.map((value) => (
                                    <span
                                      className="rounded-md border border-cyan-300/15 bg-cyan-300/10 px-3 py-1 font-mono text-xs text-cyan-100"
                                      key={`${group.label}-${value}`}
                                    >
                                      {value}
                                    </span>
                                  ))
                                ) : (
                                  <span className="text-sm text-slate-500">None returned</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </motion.section>
                ) : (
                  <motion.section
                    animate={{ opacity: 1, y: 0 }}
                    className="panel grid min-h-[280px] place-items-center p-8 text-center"
                    exit={{ opacity: 0, y: 12 }}
                    initial={{ opacity: 0, y: 18 }}
                    key="empty"
                  >
                    <div className="max-w-xl">
                      <div className="mx-auto grid h-16 w-16 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 shadow-[0_0_32px_rgba(34,211,238,0.14)]">
                        <Terminal aria-hidden="true" className="h-7 w-7 text-cyan-100" />
                      </div>
                      <h2 className="mt-5 text-2xl font-semibold text-white">Awaiting target identity</h2>
                      <p className="mt-3 text-sm leading-7 text-slate-400">
                        Identity queue is idle. The relay is standing by for a target and a sealed intelligence packet.
                      </p>
                    </div>
                  </motion.section>
                )}
              </AnimatePresence>
            </div>

            <aside className="flex min-w-0 flex-col gap-4">
              <MiniTrafficChart />
              <NodeMap />

              <div className="panel p-5">
                <div className="mb-4 flex items-center justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase text-slate-400">Live relay logs</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">Terminal feed</h2>
                  </div>
                  <Bell aria-hidden="true" className="h-5 w-5 text-emerald-200" />
                </div>
                <div className="grid max-h-[278px] gap-2 overflow-hidden font-mono text-xs">
                  {logs.map((log, index) => (
                    <motion.p
                      animate={{ opacity: 1, x: 0 }}
                      className={classNames(
                        "truncate rounded-md border border-white/10 bg-black/25 px-3 py-2",
                        index === 0 ? "text-emerald-100" : "text-slate-500",
                      )}
                      initial={{ opacity: 0, x: -8 }}
                      key={`${log}-${index}`}
                    >
                      {log}
                    </motion.p>
                  ))}
                </div>
              </div>

              <div className="panel p-5">
                <div className="mb-4 flex items-center justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase text-slate-400">Search history</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">Saved investigations</h2>
                  </div>
                  <History aria-hidden="true" className="h-5 w-5 text-cyan-200" />
                </div>
                <div className="grid gap-3">
                  {history.length ? (
                    history.map((item) => (
                      <button
                        className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-left transition hover:border-cyan-300/30 hover:bg-cyan-300/10"
                        key={`${item.email}-${item.scannedAt}`}
                        onClick={() => {
                          setEmail(item.email);
                          inputRef.current?.focus();
                        }}
                        type="button"
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="min-w-0 truncate font-mono text-sm text-slate-100">{item.email}</span>
                          <span className={classNames("rounded-md border px-2 py-1 text-[10px] uppercase", severityClass(item.riskLevel))}>
                            {item.riskLevel}
                          </span>
                        </div>
                        <p className="mt-2 text-xs text-slate-500">
                          {item.totalMatches} matches at {formatTime(item.scannedAt)}
                        </p>
                      </button>
                    ))
                  ) : (
                    <p className="rounded-lg border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                      No local investigations saved yet.
                    </p>
                  )}
                </div>
              </div>

              <div className="panel p-5">
                <div className="mb-4 flex items-center gap-3">
                  <Gauge aria-hidden="true" className="h-5 w-5 text-amber-200" />
                  <div>
                    <p className="text-xs uppercase text-slate-400">Operational status</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">Relay health</h2>
                  </div>
                </div>
                <div className="grid gap-3 text-sm">
                  {[
                    ["API vault", "Isolated"],
                    ["Rate limit", "8/min"],
                    ["Transport", "TLS"],
                    ["Cache", "Local 5m"],
                  ].map(([label, value]) => (
                    <div className="flex items-center justify-between gap-3" key={label}>
                      <span className="text-slate-500">{label}</span>
                      <span className="font-mono text-slate-200">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </aside>
          </section>
        </section>
      </div>
    </main>
  );
}
