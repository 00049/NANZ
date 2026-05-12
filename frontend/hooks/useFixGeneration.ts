'use client';

import { useState, useCallback, useRef } from 'react';
import { useAuthStore } from '@/store/authStore';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── Types matching backend FixResponse schema ────────────────────────────────

export interface FixStep {
  order: number;
  title: string;
  description: string;
  code_snippet: string | null;
  code_language: string | null;
}

export interface FixResponse {
  finding_id: string;
  summary: string;
  impact: string;
  steps: FixStep[];
  verification: string;
  verification_command: string | null;
  estimated_minutes: number;
  difficulty: 'easy' | 'medium' | 'hard';
  references: string[];
  cached: boolean;
}

export interface FixRequestPayload {
  finding_id: string;
  finding_title: string;
  finding_description: string;
  finding_detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  target_domain: string;
  scan_id: string;
}

interface UseFixGenerationReturn {
  fixData: FixResponse | null;
  isLoading: boolean;
  isStreaming: boolean;
  error: string | null;
  rawStream: string;
  generate: (payload: FixRequestPayload) => Promise<void>;
  reset: () => void;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useFixGeneration(): UseFixGenerationReturn {
  const [fixData, setFixData] = useState<FixResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rawStream, setRawStream] = useState('');
  const abortRef = useRef<AbortController | null>(null);
  const token = useAuthStore((state) => state.token);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setFixData(null);
    setIsLoading(false);
    setIsStreaming(false);
    setError(null);
    setRawStream('');
  }, []);

  const generate = useCallback(async (payload: FixRequestPayload) => {
    // Reset prior state
    setFixData(null);
    setError(null);
    setRawStream('');
    setIsLoading(true);
    setIsStreaming(false);

    // Abort any in-flight request
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    // ── Try SSE streaming endpoint first ──────────────────────────────────
    try {
      const streamRes = await fetch(`${API_BASE}/api/v1/findings/fix/stream`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (streamRes.ok && streamRes.body) {
        setIsLoading(false);
        setIsStreaming(true);

        const reader = streamRes.body.getReader();
        const decoder = new TextDecoder();
        let accumulated = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split('\n');

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const data = line.slice(6); // strip "data: "

            if (data === '[DONE]') {
              // Parse accumulated JSON
              const parsed = tryParseFixJSON(accumulated, payload.finding_id);
              if (parsed) {
                setFixData(parsed);
              } else {
                setError('Failed to parse fix response. Please try again.');
              }
              setIsStreaming(false);
              return;
            }

            // Check for error payload
            if (isErrorPayload(data)) {
              setError(extractErrorMessage(data));
              setIsStreaming(false);
              return;
            }

            accumulated += data;
            setRawStream(accumulated);
          }
        }

        // Stream ended without [DONE] — try parsing what we have
        if (accumulated.trim()) {
          const parsed = tryParseFixJSON(accumulated, payload.finding_id);
          if (parsed) {
            setFixData(parsed);
          } else {
            setError('Stream ended unexpectedly. Please retry.');
          }
        }
        setIsStreaming(false);
        return;
      }

      // If stream endpoint returns non-ok (e.g. 404), fall through to non-streaming
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      // Stream endpoint unavailable — fall back to non-streaming
    }

    // ── Fallback: non-streaming endpoint ──────────────────────────────────
    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/fix`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!res.ok) {
        const body: { detail?: string } | null = await res.json().catch(() => null);
        setError(body?.detail ?? `Fix generation failed (${res.status})`);
        setIsLoading(false);
        return;
      }

      const data = (await res.json()) as FixResponse;
      setFixData(data);
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsStreaming(false);
    }
  }, [token]);

  return { fixData, isLoading, isStreaming, error, rawStream, generate, reset };
}

// ─── JSON parser: strip markdown fences AND preamble text ─────────────────────

function extractJSON(raw: string): string {
  let cleaned = raw.trim();

  // Strip markdown fences
  if (cleaned.startsWith('```json')) {
    cleaned = cleaned.slice(7).trim();
  }
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.slice(3).trim();
  }
  if (cleaned.endsWith('```')) {
    cleaned = cleaned.slice(0, -3).trim();
  }

  // Strip everything before the first `{` and after the last `}`
  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    cleaned = cleaned.slice(firstBrace, lastBrace + 1);
  }

  return cleaned;
}

interface RawFixPayload {
  summary?: string;
  impact?: string;
  steps?: FixStep[];
  verification?: string;
  verification_command?: string | null;
  estimated_minutes?: number;
  difficulty?: 'easy' | 'medium' | 'hard';
  references?: string[];
  cached?: boolean;
}

function tryParseFixJSON(raw: string, findingId: string): FixResponse | null {
  try {
    const cleaned = extractJSON(raw);
    const parsed: RawFixPayload = JSON.parse(cleaned) as RawFixPayload;
    return {
      finding_id: findingId,
      summary: parsed.summary ?? '',
      impact: parsed.impact ?? '',
      steps: Array.isArray(parsed.steps) ? parsed.steps : [],
      verification: parsed.verification ?? '',
      verification_command: parsed.verification_command ?? null,
      estimated_minutes: parsed.estimated_minutes ?? 0,
      difficulty: parsed.difficulty ?? 'medium',
      references: Array.isArray(parsed.references) ? parsed.references : [],
      cached: parsed.cached ?? false,
    };
  } catch {
    return null;
  }
}

// ─── Error payload detection (typed, no `any`) ───────────────────────────────

function isErrorPayload(data: string): boolean {
  try {
    const parsed: unknown = JSON.parse(data);
    return (
      typeof parsed === 'object' &&
      parsed !== null &&
      'error' in parsed &&
      typeof (parsed as { error: unknown }).error === 'string'
    );
  } catch {
    return false;
  }
}

function extractErrorMessage(data: string): string {
  try {
    const parsed = JSON.parse(data) as { error: string };
    return parsed.error;
  } catch {
    return 'Unknown error from server';
  }
}
