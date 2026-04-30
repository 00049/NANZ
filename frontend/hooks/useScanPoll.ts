import { useEffect, useState } from 'react';
import { useScanStore } from '../store/scanStore';
import { getScanProgress } from '../lib/api';

export function useScanPoll() {
  const { scanId, scanStatus, setStatus, updateProgress } = useScanStore();
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!scanId || scanStatus === 'complete' || scanStatus === 'failed') return;

    const poll = async () => {
      try {
        const data = await getScanProgress(scanId);
        updateProgress(data.progress || {});
        if (data.status === 'completed' || data.status === 'complete') {
          setStatus('complete');
        } else if (data.status === 'failed') {
          setStatus('failed');
        } else {
          setStatus('running');
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    };

    setIsLoading(true);
    poll(); // Initial fetch
    const interval = setInterval(poll, 3000);

    return () => {
      clearInterval(interval);
      setIsLoading(false);
    };
  }, [scanId, scanStatus, setStatus, updateProgress]);

  return { isLoading };
}
