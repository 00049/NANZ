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
  title: "ShieldCheck — 29-Module Security Audit | DPDP Compliance | ₹499",
  description: "Enterprise cybersecurity audit for Indian businesses. 29 passive scan modules, DPDP Act compliance mapping, EPSS-enriched CVE intelligence, plain-English reports with financial risk quantification. ₹499 one-time.",
  keywords: ["DPDP compliance", "website security audit India", "cybersecurity MSME", "OWASP scanner India", "EPSS vulnerability scanner", "security headers checker", "SBOM generator", "NANZ"],
  openGraph: {
    title: "ShieldCheck — 29-Module Security Audit | DPDP Compliance | ₹499",
    description: "Enterprise security intelligence at an Indian price. 29 passive scan modules, DPDP compliance mapping, EPSS-enriched CVE intelligence, plain-English reports. ₹499 one-time.",
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
