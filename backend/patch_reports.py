import re

with open('app/routers/reports.py', 'r') as f:
    content = f.read()

# Replace user_has_paid_plan checks since we removed the plan column
content = content.replace("user_has_paid_plan = current_user and getattr(current_user, 'plan', None) == 'paid'", "user_has_paid_plan = False")

# Add payment check to enterprise and ASPM endpoints
def add_check(endpoint_name, content_str):
    pattern = r"(@router\.get\(\"\/\{scan_id\}\/" + endpoint_name + r"\".*?def .*?:\n.*?)\n(    result = await db\.execute)"
    replacement = r"""\1
    # Check if paid
    scan = await verify_report_access(scan_id, request, db)
    report_check_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report_check = report_check_result.scalars().first()
    if not report_check:
        raise HTTPException(status_code=404, detail="Report not found")
    if scan.scan_type == "free" and not report_check.is_paid:
        raise HTTPException(status_code=402, detail="Payment required to access this module")
        
\2"""
    # Wait, the endpoints don't have `request: Request` injected.
    return content_str

# A simpler way is to just use a multi_replace_file_content tool.
