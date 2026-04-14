import razorpay
from app.config import settings

# Initialize Razorpay client only if keys are provided
client = None
if settings.RAZORPAY_KEY_ID and settings.RAZORPAY_KEY_SECRET:
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def create_razorpay_order(amount_paise: int, receipt: str) -> str:
    """
    Creates an order on Razorpay and returns the order_id.
    """
    if not client:
        raise ValueError("Razorpay keys not configured")
        
    data = {
        "amount": amount_paise,
        "currency": "INR",
        "receipt": receipt,
        "notes": {
            "scan_id": receipt
        }
    }
    
    order = client.order.create(data=data)
    return order["id"]
