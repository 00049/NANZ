with open("app/services/scanner/orchestrator.py", "r") as f:
    code = f.read()

target = """                    if not all_failed:
                        report = Report(
                            scan_id=scan.id,
                            overall_severity=overall_severity,
                            overall_score=overall_score,
                            risk_items=ai_items_dict,
                            ai_summary=exec_summary,
                            executive_summary=exec_summary,"""

replacement = """                    if True:
                        report = Report(
                            scan_id=scan.id,
                            overall_severity="CRITICAL" if all_failed else overall_severity,
                            overall_score=0 if all_failed else overall_score,
                            risk_items=[] if all_failed else ai_items_dict,
                            ai_summary="Scan failed. Detailed AI analysis is currently unavailable." if all_failed else exec_summary,
                            executive_summary="Scan failed." if all_failed else exec_summary,"""

if target in code:
    code = code.replace(target, replacement)
    with open("app/services/scanner/orchestrator.py", "w") as f:
        f.write(code)
    print("Patched successfully!")
else:
    print("Target not found!")
