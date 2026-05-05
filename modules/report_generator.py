"""
SIEM PDF Report Generator
Generates a professional security report from detected alerts.
"""

import os
import platform
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Colors ────────────────────────────────────────────────────────────────────
C_BG        = colors.HexColor('#080c10')
C_PANEL     = colors.HexColor('#0d1117')
C_ACCENT    = colors.HexColor('#00ff95')
C_BLUE      = colors.HexColor('#00b8ff')
C_RED       = colors.HexColor('#ff4d6d')
C_ORANGE    = colors.HexColor('#ff8c42')
C_YELLOW    = colors.HexColor('#ffd166')
C_GREEN     = colors.HexColor('#06d6a0')
C_DIM       = colors.HexColor('#6e7681')
C_TEXT      = colors.HexColor('#c9d1d9')
C_WHITE     = colors.white
C_BLACK     = colors.HexColor('#0d1117')
C_BORDER    = colors.HexColor('#1a2332')

SEVERITY_COLORS = {
    'CRITICAL': C_RED,
    'HIGH':     C_ORANGE,
    'MEDIUM':   C_YELLOW,
    'LOW':      C_GREEN,
}

SEVERITY_BG = {
    'CRITICAL': colors.HexColor('#2d0a10'),
    'HIGH':     colors.HexColor('#2d1a08'),
    'MEDIUM':   colors.HexColor('#2d2608'),
    'LOW':      colors.HexColor('#082d1e'),
}


def get_styles():
    """Define all paragraph styles."""
    styles = getSampleStyleSheet()

    return {
        'title': ParagraphStyle(
            'title', fontName='Helvetica-Bold', fontSize=28,
            textColor=C_ACCENT, alignment=TA_CENTER, spaceAfter=4
        ),
        'subtitle': ParagraphStyle(
            'subtitle', fontName='Helvetica', fontSize=12,
            textColor=C_DIM, alignment=TA_CENTER, spaceAfter=2
        ),
        'section': ParagraphStyle(
            'section', fontName='Helvetica-Bold', fontSize=13,
            textColor=C_ACCENT, spaceBefore=16, spaceAfter=8,
            borderPad=4
        ),
        'body': ParagraphStyle(
            'body', fontName='Helvetica', fontSize=9,
            textColor=C_TEXT, spaceAfter=4, leading=14
        ),
        'body_dim': ParagraphStyle(
            'body_dim', fontName='Helvetica', fontSize=9,
            textColor=C_DIM, spaceAfter=4, leading=14
        ),
        'mono': ParagraphStyle(
            'mono', fontName='Courier', fontSize=8,
            textColor=C_BLUE, spaceAfter=2
        ),
        'status_clean': ParagraphStyle(
            'status_clean', fontName='Helvetica-Bold', fontSize=14,
            textColor=C_GREEN, alignment=TA_CENTER, spaceAfter=6
        ),
        'status_attacked': ParagraphStyle(
            'status_attacked', fontName='Helvetica-Bold', fontSize=14,
            textColor=C_RED, alignment=TA_CENTER, spaceAfter=6
        ),
        'small': ParagraphStyle(
            'small', fontName='Helvetica', fontSize=8,
            textColor=C_DIM, spaceAfter=2
        ),
        'centered': ParagraphStyle(
            'centered', fontName='Helvetica', fontSize=9,
            textColor=C_TEXT, alignment=TA_CENTER
        ),
    }


def severity_badge(severity):
    """Return colored severity text for table cells."""
    color_map = {
        'CRITICAL': '#ff4d6d',
        'HIGH':     '#ff8c42',
        'MEDIUM':   '#ffd166',
        'LOW':      '#06d6a0',
    }
    c = color_map.get(severity, '#6e7681')
    return f'<font color="{c}"><b>{severity}</b></font>'


def generate_report(alerts, scan_info, output_path):
    """
    Generate a professional PDF security report.

    Args:
        alerts:      List of alert dicts from detector.py
        scan_info:   Dict with scan metadata (filename, events_found, etc.)
        output_path: Where to save the PDF
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=15*mm, bottomMargin=15*mm,
        title="SIEM Security Report"
    )

    styles  = get_styles()
    W       = A4[0] - 40*mm  # usable width
    story   = []
    now     = datetime.now()
    os_name = platform.system() + ' ' + platform.release()

    # ── COVER PAGE ─────────────────────────────────────────────────────────────

    story.append(Spacer(1, 20*mm))

    # Logo / Title block
    cover_data = [[
        Paragraph('🛡️  SIEM', ParagraphStyle(
            'logo', fontName='Helvetica-Bold', fontSize=36,
            textColor=C_ACCENT, alignment=TA_CENTER
        ))
    ]]
    cover_table = Table(cover_data, colWidths=[W])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_PANEL),
        ('ROUNDEDCORNERS', [8]),
        ('BOX', (0,0), (-1,-1), 1, C_ACCENT),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph('Security Information & Event Management', styles['subtitle']))
    story.append(Paragraph('SECURITY INCIDENT REPORT', ParagraphStyle(
        'report_title', fontName='Helvetica-Bold', fontSize=20,
        textColor=C_TEXT, alignment=TA_CENTER, spaceAfter=4
    )))
    story.append(Spacer(1, 8*mm))

    # Meta info table
    meta_data = [
        ['Report Generated', now.strftime('%Y-%m-%d %H:%M:%S')],
        ['System / OS',      os_name],
        ['Log File',         scan_info.get('filename', 'Unknown')],
        ['Log Format',       scan_info.get('log_type', 'Unknown').upper()],
        ['Events Analysed',  str(scan_info.get('events_found', 0))],
        ['Total Alerts',     str(len(alerts))],
    ]
    meta_table = Table(meta_data, colWidths=[60*mm, W - 60*mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (0, -1), C_PANEL),
        ('BACKGROUND',   (1, 0), (1, -1), colors.HexColor('#111827')),
        ('TEXTCOLOR',    (0, 0), (0, -1), C_DIM),
        ('TEXTCOLOR',    (1, 0), (1, -1), C_TEXT),
        ('FONTNAME',     (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',     (1, 0), (1, -1), 'Courier'),
        ('FONTSIZE',     (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[C_PANEL, colors.HexColor('#111827')]),
        ('BOX',          (0, 0), (-1, -1), 1, C_BORDER),
        ('INNERGRID',    (0, 0), (-1, -1), 0.5, C_BORDER),
        ('TOPPADDING',   (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
        ('LEFTPADDING',  (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    # Overall status banner
    critical_count = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
    high_count     = sum(1 for a in alerts if a['severity'] == 'HIGH')
    medium_count   = sum(1 for a in alerts if a['severity'] == 'MEDIUM')
    low_count      = sum(1 for a in alerts if a['severity'] == 'LOW')

    if not alerts:
        status_text  = '✅  SYSTEM IS CLEAN — No attacks detected'
        status_color = C_GREEN
        status_bg    = colors.HexColor('#082d1e')
    elif critical_count:
        status_text  = f'🚨  SYSTEM UNDER ATTACK — {critical_count} Critical, {high_count} High alerts'
        status_color = C_RED
        status_bg    = colors.HexColor('#2d0a10')
    elif high_count:
        status_text  = f'⚠️  SUSPICIOUS ACTIVITY — {high_count} High severity alerts'
        status_color = C_ORANGE
        status_bg    = colors.HexColor('#2d1a08')
    else:
        status_text  = f'ℹ️  LOW RISK — {len(alerts)} minor alert(s) found'
        status_color = C_BLUE
        status_bg    = colors.HexColor('#081e2d')

    status_data = [[Paragraph(status_text, ParagraphStyle(
        'st', fontName='Helvetica-Bold', fontSize=13,
        textColor=status_color, alignment=TA_CENTER
    ))]]
    status_table = Table(status_data, colWidths=[W])
    status_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), status_bg),
        ('BOX',           (0,0), (-1,-1), 1.5, status_color),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(status_table)

    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────────────

    story.append(Paragraph('1.  Executive Summary', styles['section']))
    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceAfter=8))

    # Severity breakdown cards
    sev_data = [[
        Paragraph(f'<b><font color="#ff4d6d">{critical_count}</font></b><br/><font color="#6e7681" size="8">CRITICAL</font>', styles['centered']),
        Paragraph(f'<b><font color="#ff8c42">{high_count}</font></b><br/><font color="#6e7681" size="8">HIGH</font>', styles['centered']),
        Paragraph(f'<b><font color="#ffd166">{medium_count}</font></b><br/><font color="#6e7681" size="8">MEDIUM</font>', styles['centered']),
        Paragraph(f'<b><font color="#06d6a0">{low_count}</font></b><br/><font color="#6e7681" size="8">LOW</font>', styles['centered']),
        Paragraph(f'<b><font color="#00ff95">{len(alerts)}</font></b><br/><font color="#6e7681" size="8">TOTAL</font>', styles['centered']),
    ]]
    sev_table = Table(sev_data, colWidths=[W/5]*5)
    sev_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), C_PANEL),
        ('BOX',           (0,0), (-1,-1), 1, C_BORDER),
        ('INNERGRID',     (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING',    (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('FONTSIZE',      (0,0), (-1,-1), 18),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 6*mm))

    # Summary text
    if not alerts:
        summary = "Analysis of the provided log file revealed no security incidents. The system appears to be operating normally with no signs of unauthorized access or malicious activity."
    else:
        attack_types = list(set(a['alert_type'] for a in alerts))
        attacker_ips = list(set(a['source_ip'] for a in alerts if a['source_ip'] not in ('N/A', 'localhost', '127.0.0.1 (localhost)')))
        summary = (
            f"Analysis of <b>{scan_info.get('filename', 'the log file')}</b> detected "
            f"<font color='#ff4d6d'><b>{len(alerts)} security alert(s)</b></font> across "
            f"{len(attack_types)} attack type(s). "
        )
        if attacker_ips:
            summary += f"Primary threat source(s): <font color='#00ff95'><b>{', '.join(attacker_ips[:3])}</b></font>. "
        if critical_count:
            summary += f"Immediate action is required for {critical_count} CRITICAL alert(s). "
        summary += "Full details are provided in Section 3."

    story.append(Paragraph(summary, styles['body']))
    story.append(Spacer(1, 4*mm))

    # MITRE tactics detected
    tactics = list(set(a.get('mitre_tactic', '') for a in alerts if a.get('mitre_tactic')))
    if tactics:
        story.append(Paragraph('MITRE ATT&CK Tactics Observed:', styles['body']))
        tactic_data = [[Paragraph(f'• {t}', styles['body_dim'])] for t in tactics]
        tactic_table = Table(tactic_data, colWidths=[W])
        tactic_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_PANEL),
            ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(tactic_table)

    story.append(Spacer(1, 6*mm))

    # ── ATTACK TIMELINE ────────────────────────────────────────────────────────

    if alerts:
        story.append(Paragraph('2.  Attack Timeline', styles['section']))
        story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceAfter=8))

        timeline_data = [
            [
                Paragraph('<b><font color="#6e7681">TIME</font></b>', styles['small']),
                Paragraph('<b><font color="#6e7681">ALERT TYPE</font></b>', styles['small']),
                Paragraph('<b><font color="#6e7681">SEVERITY</font></b>', styles['small']),
                Paragraph('<b><font color="#6e7681">SOURCE IP</font></b>', styles['small']),
            ]
        ]
        for a in alerts:
            ts = a.get('timestamp', '')
            if ' ' in ts:
                ts = ts.split(' ')[1]  # just time part
            timeline_data.append([
                Paragraph(f'<font color="#6e7681">{ts}</font>', styles['mono']),
                Paragraph(f'<font color="#c9d1d9">{a["alert_type"]}</font>', styles['body']),
                Paragraph(severity_badge(a['severity']), styles['body']),
                Paragraph(f'<font color="#00ff95">{a["source_ip"]}</font>', styles['mono']),
            ])

        col_w = [25*mm, W - 25*mm - 25*mm - 45*mm, 25*mm, 45*mm]
        tl_table = Table(timeline_data, colWidths=col_w, repeatRows=1)
        tl_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1,  0), colors.HexColor('#111827')),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [C_PANEL, colors.HexColor('#0a0f16')]),
            ('BOX',           (0, 0), (-1, -1), 1, C_BORDER),
            ('INNERGRID',     (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING',    (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(tl_table)
        story.append(Spacer(1, 6*mm))

    # ── DETAILED ALERTS ────────────────────────────────────────────────────────

    story.append(Paragraph('3.  Detailed Security Alerts', styles['section']))
    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceAfter=8))

    if not alerts:
        story.append(Paragraph('✅  No security alerts were detected in this log file.', styles['body']))
    else:
        for i, alert in enumerate(alerts, 1):
            sev   = alert['severity']
            sev_c = SEVERITY_COLORS.get(sev, C_DIM)
            sev_b = SEVERITY_BG.get(sev, C_PANEL)

            # Alert header
            header_data = [[
                Paragraph(f'<b><font color="{sev_c.hexval() if hasattr(sev_c,"hexval") else "#ffffff"}">[{sev}]</font>  Alert #{i}: {alert["alert_type"]}</b>',
                    ParagraphStyle('ah', fontName='Helvetica-Bold', fontSize=10, textColor=sev_c)
                )
            ]]
            header_table = Table(header_data, colWidths=[W])
            header_table.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,-1), sev_b),
                ('BOX',           (0,0), (-1,-1), 1, sev_c),
                ('LEFTPADDING',   (0,0), (-1,-1), 10),
                ('TOPPADDING',    (0,0), (-1,-1), 7),
                ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ]))
            story.append(header_table)

            # Alert details
            detail_data = [
                ['Source IP',    alert.get('source_ip', 'N/A')],
                ['MITRE ID',     f"{alert.get('mitre_id', '')} — {alert.get('mitre_name', '')}"],
                ['Tactic',       alert.get('mitre_tactic', 'N/A')],
                ['Evidence',     f"{alert.get('evidence_count', 0)} event(s)"],
                ['Description',  alert.get('description', 'N/A')],
            ]
            det_table = Table(detail_data, colWidths=[30*mm, W - 30*mm])
            det_table.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor('#111827')),
                ('BACKGROUND',    (1, 0), (1, -1), C_PANEL),
                ('TEXTCOLOR',     (0, 0), (0, -1), C_DIM),
                ('TEXTCOLOR',     (1, 0), (1, -1), C_TEXT),
                ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME',      (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE',      (0, 0), (-1, -1), 8.5),
                ('BOX',           (0, 0), (-1, -1), 1, C_BORDER),
                ('INNERGRID',     (0, 0), (-1, -1), 0.5, C_BORDER),
                ('TOPPADDING',    (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(det_table)
            story.append(Spacer(1, 4*mm))

    # ── RECOMMENDATIONS ────────────────────────────────────────────────────────

    story.append(PageBreak())
    story.append(Paragraph('4.  Recommendations', styles['section']))
    story.append(HRFlowable(width=W, thickness=1, color=C_BORDER, spaceAfter=8))

    # Build recommendations based on what was detected
    alert_types = [a['alert_type'] for a in alerts]
    recs = []

    if any('Brute Force' in t or 'SSH' in t for t in alert_types):
        recs.append(('SSH Brute Force Detected', [
            'Enable fail2ban to automatically block IPs after repeated failures',
            'Disable root SSH login: set PermitRootLogin no in /etc/ssh/sshd_config',
            'Use SSH key authentication instead of passwords',
            'Change SSH port from default 22 to a non-standard port',
            'Implement Multi-Factor Authentication (MFA)',
        ]))

    if any('SQL Injection' in t for t in alert_types):
        recs.append(('SQL Injection Detected', [
            'Use parameterized queries / prepared statements in all database code',
            'Implement a Web Application Firewall (WAF)',
            'Sanitize and validate all user inputs server-side',
            'Apply principle of least privilege to database accounts',
        ]))

    if any('Scanning' in t or 'Traversal' in t for t in alert_types):
        recs.append(('Web Scanning / Directory Traversal Detected', [
            'Block scanning user agents at the web server level',
            'Remove or restrict access to sensitive paths (.env, .git, admin)',
            'Enable rate limiting on your web server',
            'Review and restrict directory listing permissions',
        ]))

    if any('Backdoor' in t or 'Malware' in t for t in alert_types):
        recs.append(('Malware / Backdoor Activity Detected', [
            'IMMEDIATELY isolate this system from the network',
            'Run a full antivirus/rootkit scan',
            'Check all running processes and cron jobs for malicious entries',
            'Review recently modified files in /tmp, /var/tmp',
            'Consider full system reimaging',
        ]))

    if any('Exfiltration' in t for t in alert_types):
        recs.append(('Data Exfiltration Detected', [
            'Block outbound connections to the attacker IP immediately',
            'Review what data was accessed and exfiltrated',
            'Notify affected parties if sensitive data was compromised',
            'Implement Data Loss Prevention (DLP) controls',
        ]))

    if not recs:
        recs.append(('General Security Hardening', [
            'Keep all software and OS packages updated regularly',
            'Enable and review system logs daily',
            'Implement network segmentation',
            'Run regular vulnerability scans',
            'Enable Multi-Factor Authentication on all accounts',
        ]))

    for title, items in recs:
        story.append(Paragraph(f'▸  {title}', ParagraphStyle(
            'rec_title', fontName='Helvetica-Bold', fontSize=10,
            textColor=C_BLUE, spaceBefore=8, spaceAfter=4
        )))
        rec_data = [[Paragraph(f'• {item}', styles['body'])] for item in items]
        rec_table = Table(rec_data, colWidths=[W])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_PANEL),
            ('BOX',        (0,0), (-1,-1), 0.5, C_BORDER),
            ('LEFTPADDING',(0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ]))
        story.append(rec_table)

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f'Generated by SIEM — Security Information & Event Management System  |  {now.strftime("%Y-%m-%d %H:%M:%S")}  |  Confidential',
        ParagraphStyle('footer', fontName='Helvetica', fontSize=7, textColor=C_DIM, alignment=TA_CENTER)
    ))

    # Build PDF
    doc.build(story)
    print(f"[+] Report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    # Test with sample alerts
    sample_alerts = [
        {"alert_type": "SSH Brute Force", "severity": "CRITICAL", "source_ip": "185.234.219.12",
         "description": "IP 185.234.219.12 made 25 failed SSH login attempts.", "evidence_count": 25,
         "mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access",
         "timestamp": "2026-04-19 10:30:01"},
        {"alert_type": "Brute Force Success", "severity": "CRITICAL", "source_ip": "185.234.219.12",
         "description": "Attacker logged in as 'manoj' after 25 failures.", "evidence_count": 26,
         "mitre_id": "T1110", "mitre_name": "Brute Force", "mitre_tactic": "Credential Access",
         "timestamp": "2026-04-19 10:32:35"},
        {"alert_type": "Privilege Escalation Detected", "severity": "CRITICAL", "source_ip": "N/A",
         "description": "sudo /bin/bash executed — attacker gained root.", "evidence_count": 1,
         "mitre_id": "T1548", "mitre_name": "Abuse Elevation Control", "mitre_tactic": "Privilege Escalation",
         "timestamp": "2026-04-19 10:33:01"},
        {"alert_type": "Web Scanning / Directory Traversal", "severity": "HIGH", "source_ip": "103.75.190.11",
         "description": "177 suspicious web requests detected. Nikto scanner identified.", "evidence_count": 177,
         "mitre_id": "T1595", "mitre_name": "Active Scanning", "mitre_tactic": "Reconnaissance",
         "timestamp": "2026-04-19 10:45:00"},
        {"alert_type": "SQL Injection Attempt", "severity": "CRITICAL", "source_ip": "103.75.190.11",
         "description": "6 SQL injection payloads detected in web requests.", "evidence_count": 6,
         "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing App", "mitre_tactic": "Initial Access",
         "timestamp": "2026-04-19 10:46:22"},
    ]

    scan_info = {
        "filename":     "linux_auth.log",
        "log_type":     "ssh",
        "events_found": 52,
    }

    output = generate_report(sample_alerts, scan_info, "/tmp/siem_report_test.pdf")
    print(f"Test report saved to: {output}")
