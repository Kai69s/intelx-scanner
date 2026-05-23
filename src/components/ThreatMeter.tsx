"use client";

import { motion } from "framer-motion";
import type { RiskLevel } from "@/lib/types";

const riskScore: Record<RiskLevel, number> = {
  clear: 8,
  guarded: 25,
  elevated: 52,
  high: 76,
  critical: 96,
};

const riskTone: Record<RiskLevel, string> = {
  clear: "text-emerald-200",
  guarded: "text-cyan-200",
  elevated: "text-amber-200",
  high: "text-orange-200",
  critical: "text-red-200",
};

export function ThreatMeter({ level }: { level: RiskLevel }) {
  const score = riskScore[level];

  return (
    <div className="panel p-5">
      <div className="mb-4 flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase text-slate-400">Threat meter</p>
          <h2 className={`mt-1 text-2xl font-semibold ${riskTone[level]}`}>{level.toUpperCase()}</h2>
        </div>
        <div className="text-right font-mono text-sm text-cyan-200">
          {score}
          <span className="text-slate-500">/100</span>
        </div>
      </div>
      <div className="relative h-3 overflow-hidden rounded-md border border-white/10 bg-black/50">
        <div className="absolute inset-0 bg-gradient-to-r from-emerald-400 via-cyan-300 via-amber-300 to-red-400 opacity-80" />
        <motion.div
          aria-hidden="true"
          animate={{ x: `${score}%` }}
          className="absolute top-[-5px] h-7 w-1 bg-white shadow-[0_0_18px_rgba(255,255,255,0.95)]"
          initial={{ x: 0 }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
      </div>
      <div className="mt-4 grid grid-cols-5 gap-1 text-[10px] uppercase text-slate-500">
        <span>Clear</span>
        <span>Guarded</span>
        <span>Elevated</span>
        <span>High</span>
        <span>Critical</span>
      </div>
    </div>
  );
}
