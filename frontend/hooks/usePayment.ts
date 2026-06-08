import { useState, useEffect } from 'react';
import { createPaymentOrder, verifyPayment } from '../lib/api';
import { useScanStore } from '../store/scanStore';

declare global {
  interface Window {
    Razorpay: any;
  }
}

export function usePayment() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { setReportJWT } = useScanStore();

  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    document.body.appendChild(script);
    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const openPayment = async (scanId: string, email: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const order = await createPaymentOrder(scanId, email);
      
      const options = {
        key: order.key_id,
        amount: order.amount,
        currency: order.currency,
        name: "NANZ",
        description: "Full Security Report",
        order_id: order.order_id,
        handler: async function (response: any) {
          try {
            const verifyRes = await verifyPayment({
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
              email
            });
            setReportJWT(verifyRes.access_token);
            useScanStore.setState({ isPaid: true });
            if (typeof window !== 'undefined') {
              localStorage.setItem(`paid_scan_${scanId}`, 'true');
            }
          } catch (err: any) {
            setError(err.message || 'Payment verification failed');
          }
        },
        prefill: { email },
        theme: { color: "#3B82F6" }
      };

      const rzp = new window.Razorpay(options);
      rzp.on('payment.failed', function (response: any) {
        setError(response.error.description);
      });
      rzp.open();
    } catch (err: any) {
      setError(err.message || 'Failed to initialize payment');
    } finally {
      setIsLoading(false);
    }
  };

  return { openPayment, isLoading, error };
}
