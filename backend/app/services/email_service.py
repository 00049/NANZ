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
        overall = report_data.get("overall_severity", "GREEN")
        color = "#10B981" if overall == "GREEN" else "#F59E0B" if overall == "AMBER" else "#EF4444"
        
        cards_html = ""
        for item in report_data.get("risk_items", []):
            item_color = "#10B981" if item["severity"] == "GREEN" else "#F59E0B" if item["severity"] == "AMBER" else "#EF4444"
            cards_html += f"""
            <div style="border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h3 style="margin-top: 0; color: {item_color};">{item["title"]}</h3>
                <p><strong>Impact:</strong> {item["business_impact"]}</p>
                <p><strong>Fix Action:</strong> {item["fix_action"]}</p>
            </div>
            """

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #1e3a8a; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="color: white; margin: 0;">ShieldCheck Report</h1>
            </div>
            
            <div style="padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                <h2>Security Audit for: <em>{domain}</em></h2>
                
                <div style="margin: 20px 0; padding: 10px; background-color: {color}; color: white; text-align: center; border-radius: 4px; font-weight: bold;">
                    Overall Status: {overall}
                </div>
                
                {cards_html}
            </div>
            
            <div style="margin-top: 30px; font-size: 12px; color: #6b7280; text-align: center;">
                <p>This is a risk indicator, not a security guarantee.</p>
                <p><a href="#" style="color: #6b7280;">Unsubscribe</a> from future reports.</p>
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
