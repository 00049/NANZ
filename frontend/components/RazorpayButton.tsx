// RazorpayButton — payment is currently disabled. Reports are free for all users.
// Re-enable this component and wire it when payments are re-introduced.
'use client';

export default function RazorpayButton({ scanId }: { scanId: string }) {
  // Payment disabled — reports are free for now
  void scanId;
  return null;
}
