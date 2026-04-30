import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { Providers } from "./providers";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "NANZ | AI Cybersecurity Platform",
  description: "Enterprise-grade AI-powered website security scanning, continuous monitoring, vulnerability reporting, and compliance readiness.",
  keywords: ["cybersecurity", "security scanner", "vulnerability assessment", "DPDP compliance", "website security"],
  openGraph: {
    title: "NANZ | AI Cybersecurity Platform",
    description: "Protect what you build. AI-powered security intelligence for modern businesses.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className={`${inter.variable} font-sans bg-background text-text-primary min-h-screen`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
