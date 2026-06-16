with open("app/routers/reports.py") as f:
    content = f.read()

# Replace user_has_paid_plan checks since we removed the plan column
content = content.replace(
    "user_has_paid_plan = current_user and getattr(current_user, 'plan', None) == 'paid'",
    "user_has_paid_plan = False",
)


# Add payment check to enterprise and ASPM endpoints
def add_check(endpoint_name, content_str):
    (
        r"(@router\.get\(\"\/\{scan_id\}\/"
        + endpoint_name
        + r"\".*?def .*?:\n.*?)\n(    result = await db\.execute)"
    )
    # Wait, the endpoints don't have `request: Request` injected.
    return content_str


# A simpler way is to just use a multi_replace_file_content tool.
