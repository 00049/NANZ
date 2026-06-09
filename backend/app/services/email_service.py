import resend
import logging
from app.config import settings

logger = logging.getLogger(__name__)

if settings.RESEND_API_KEY:
    resend.api_key = settings.RESEND_API_KEY

async def send_report_email(to_email: str, report_data: dict, domain: str) -> bool:
    """
    Sends the generated report via email using Resend.
    """
    if not settings.RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not configured. Skipping email.")
        return False
        
    try:
        # Build HTML content
        cards_html = ""
        for item in report_data.get("risk_items", []):
            sev = item["severity"]
            if sev in ["CRITICAL", "HIGH", "RED"]:
                badge_bg = "#FEE2E2"
                badge_color = "#991B1B"
            elif sev in ["MEDIUM", "AMBER"]:
                badge_bg = "#FEF3C7"
                badge_color = "#92400E"
            elif sev in ["LOW", "GREEN"]:
                badge_bg = "#D1FAE5"
                badge_color = "#065F46"
            else:
                badge_bg = "#E5E7EB"
                badge_color = "#374151"

            cards_html += f"""
            <div style="border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; margin-bottom: 20px; background-color: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h3 style="margin: 0; color: #111827; font-size: 18px;">{item["title"]}</h3>
                    <span style="background-color: {badge_bg}; color: {badge_color}; padding: 4px 8px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase;">{sev}</span>
                </div>
                <p style="margin: 0 0 8px 0; color: #4B5563; font-size: 14px;"><strong>Impact:</strong> {item["business_impact"]}</p>
                <p style="margin: 0; color: #4B5563; font-size: 14px;"><strong>Fix Action:</strong> {item["fix_action"]}</p>
            </div>
            """

        overall = report_data.get("overall_severity", "GREEN")
        ov_bg = "#10B981" if overall == "GREEN" else "#F59E0B" if overall == "AMBER" else "#EF4444"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #374151; background-color: #F3F4F6; margin: 0; padding: 40px 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <div style="background-color: #1E3A8A; padding: 30px 40px; text-align: center;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 0.5px;">ShieldCheck Security Audit</h1>
                </div>
                
                <div style="padding: 40px;">
                    <h2 style="margin-top: 0; color: #111827; font-size: 20px;">Report for: <a href="https://{domain}" style="color: #2563EB; text-decoration: none;">{domain}</a></h2>
                    
                    <div style="margin: 24px 0; padding: 16px; background-color: {ov_bg}; color: white; text-align: center; border-radius: 8px; font-weight: 600; font-size: 18px; letter-spacing: 0.5px;">
                        Overall Status: {overall}
                    </div>
                    
                    <h3 style="color: #374151; font-size: 16px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px;">Key Findings</h3>
                    {cards_html}
                    
                    <div style="text-align: center; margin-top: 32px;">
                        <a href="https://shieldcheck.in/dashboard" style="background-color: #2563EB; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">View Full Report Online</a>
                    </div>
                </div>
                
                <div style="background-color: #F9FAFB; padding: 20px; text-align: center; border-top: 1px solid #E5E7EB; font-size: 12px; color: #6B7280;">
                    <p style="margin: 0 0 8px 0;">This report is an automated risk indicator, not a comprehensive security guarantee.</p>
                    <p style="margin: 0;">&copy; 2026 ShieldCheck. <a href="#" style="color: #2563EB; text-decoration: none;">Unsubscribe</a></p>
                </div>
            </div>
        </body>
        </html>
        """

        # Sync call technically as Resend python SDK isn't fully async yet for the send method
        # Should be wrapped in thread or executed via their async httpx support if needed.
        # But for this implementation, the resend SDK handles it efficiently enough.
        r = resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": [to_email],
            "subject": f"Your ShieldCheck Security Report for {domain}",
            "html": html_content
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}", exc_info=True)
        return False

def send_welcome_email(to_email: str):
    """Sent on registration."""
    if not settings.RESEND_API_KEY:
        logger.warning(f"RESEND_API_KEY not configured. Skipping email to {to_email}")
        return False
        
    subject = "Your ShieldCheck account is ready"
    login_url = f"{settings.FRONTEND_URL}/auth/login"
    
    html = f"""
    <h2>Welcome to ShieldCheck!</h2>
    <p>Your account has been created successfully with the email: <strong>{to_email}</strong>.</p>
    <p>You can now run enterprise-grade security scans and compliance checks in under 90 seconds.</p>
    <p><a href="{login_url}" style="display:inline-block;padding:10px 20px;background-color:#4F46E5;color:white;text-decoration:none;border-radius:5px;">Login to your Dashboard</a></p>
    <p>Stay secure,<br/>The ShieldCheck Team</p>
    """
    try:
        resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": to_email,
            "subject": subject,
            "html": html
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def send_report_ready_email(to_email: str, domain: str, score: int, grade: str, scan_id: str):
    """Sent when scan completes."""
    if not settings.RESEND_API_KEY:
        logger.warning(f"RESEND_API_KEY not configured. Skipping email to {to_email}")
        return False
        
    subject = f"Your security report for {domain} is ready"
    report_url = f"{settings.FRONTEND_URL}/report/{scan_id}"
    
    html = f"""
    <h2>Your scan is complete</h2>
    <p>We've finished analyzing <strong>{domain}</strong> across 28 modules.</p>
    <h3>Results:</h3>
    <ul>
        <li><strong>Security Score:</strong> {score}/100</li>
        <li><strong>Overall Grade:</strong> {grade}</li>
    </ul>
    <p><a href="{report_url}" style="display:inline-block;padding:10px 20px;background-color:#4F46E5;color:white;text-decoration:none;border-radius:5px;">View Full Report</a></p>
    <p>Thank you for using ShieldCheck.</p>
    """
    try:
        resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": to_email,
            "subject": subject,
            "html": html
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def send_payment_confirmation_email(to_email: str, domain: str, amount_inr: float, scan_id: str):
    """Sent after razorpay verification."""
    if not settings.RESEND_API_KEY:
        logger.warning(f"RESEND_API_KEY not configured. Skipping email to {to_email}")
        return False
        
    subject = f"ShieldCheck — Payment confirmed ₹{amount_inr}"
    report_url = f"{settings.FRONTEND_URL}/report/{scan_id}"
    
    html = f"""
    <h2>Payment Confirmed</h2>
    <p>Thank you for your payment of <strong>₹{amount_inr}</strong>.</p>
    <p>Your full security report for <strong>{domain}</strong> is now unlocked.</p>
    <div style="background-color:#f3f4f6;padding:15px;margin:20px 0;border-radius:5px;">
        <p><strong>Invoice Details</strong></p>
        <p>Item: Full Security Report ({domain})</p>
        <p>Amount Paid: ₹{amount_inr}</p>
    </div>
    <p><a href="{report_url}" style="display:inline-block;padding:10px 20px;background-color:#4F46E5;color:white;text-decoration:none;border-radius:5px;">Access Your Report</a></p>
    """
    try:
        resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": to_email,
            "subject": subject,
            "html": html
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False
