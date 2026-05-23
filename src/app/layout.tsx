import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { CyberBackdrop } from "@/components/CyberBackdrop";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "IntelX Scanner | Email Exposure Intelligence",
  description:
    "A cinematic OSINT-style email intelligence dashboard powered by a secure Intelbase API relay.",
  applicationName: "IntelX Scanner",
  metadataBase: new URL("https://intelx-scanner.vercel.app"),
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full">
        <CyberBackdrop />
        {children}
      </body>
    </html>
  );
}
