"""
Report Generation for PII Detection
Generates HTML and PDF reports with detected items and safeguarding recommendations
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
from pathlib import Path
import json
import logging
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate comprehensive PII detection reports in HTML and PDF formats
    """
    
    def __init__(self):
        """Initialize report generator"""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for reports"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12,
            borderColor=colors.HexColor('#007bff'),
            borderPadding=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            fontSize=11,
            textColor=colors.HexColor('#dc3545'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            fontSize=11,
            textColor=colors.HexColor('#ff6b35'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            fontSize=11,
            textColor=colors.HexColor('#28a745'),
            fontName='Helvetica-Bold'
        ))
    
    def generate_html_report(self, file_path: str, filename: str, entities: List[Dict[str, Any]], 
                           overall_risk: str, output_path: str = None) -> str:
        """
        Generate HTML report with detected PII and recommendations
        
        Args:
            file_path: Path to analyzed file
            filename: Original filename
            entities: List of detected entities
            overall_risk: Overall risk level
            output_path: Optional path to save report
            
        Returns:
            HTML report as string (and saved to file if output_path provided)
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII Detection Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        
        .header {{
            border-bottom: 3px solid #333;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            color: #1a1a1a;
            font-size: 28px;
            margin-bottom: 10px;
        }}
        
        .header-info {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 15px;
            font-size: 13px;
        }}
        
        .header-info-item {{
            display: flex;
            justify-content: space-between;
        }}
        
        .header-info-item label {{
            font-weight: 600;
            color: #555;
        }}
        
        .header-info-item value {{
            color: #333;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 20px;
        }}
        
        .risk-critical {{
            background-color: #721c24;
            color: white;
        }}
        
        .risk-high {{
            background-color: #dc3545;
            color: white;
        }}
        
        .risk-medium {{
            background-color: #ff6b35;
            color: white;
        }}
        
        .risk-low {{
            background-color: #28a745;
            color: white;
        }}
        
        .summary-section {{
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}
        
        .summary-section h2 {{
            color: #007bff;
            font-size: 18px;
            margin-bottom: 10px;
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .stat-item {{
            background-color: white;
            padding: 12px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }}
        
        .stat-label {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            font-weight: 600;
        }}
        
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-top: 8px;
        }}
        
        .entities-section {{
            margin-top: 40px;
        }}
        
        .entities-section h2 {{
            color: #333;
            font-size: 20px;
            margin-bottom: 20px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 10px;
        }}
        
        .entity-item {{
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .entity-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
            margin-bottom: 10px;
        }}
        
        .entity-type {{
            font-size: 16px;
            font-weight: bold;
            color: #333;
        }}
        
        .entity-confidence {{
            font-size: 12px;
            color: #888;
        }}
        
        .entity-content {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            width: 100%;
        }}
        
        .entity-detail {{
            flex: 1;
        }}
        
        .entity-detail-label {{
            font-weight: 600;
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        
        .entity-detail-value {{
            color: #333;
            word-break: break-word;
        }}
        
        .recommendations {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
            width: 100%;
        }}
        
        .recommendations-title {{
            font-weight: 600;
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        
        .recommendation-item {{
            background-color: white;
            border-left: 3px solid #ffc107;
            padding: 10px 12px;
            margin-bottom: 8px;
            border-radius: 2px;
            font-size: 13px;
        }}
        
        .safeguard-options {{
            margin-top: 10px;
            width: 100%;
            padding-top: 10px;
            border-top: 1px dotted #ddd;
        }}
        
        .safeguard-title {{
            font-weight: 600;
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        
        .option {{
            display: flex;
            align-items: center;
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .option:hover {{
            background-color: #007bff;
            color: white;
            border-color: #007bff;
        }}
        
        .option input[type="radio"] {{
            margin-right: 10px;
            cursor: pointer;
        }}
        
        .option-text {{
            display: flex;
            flex-direction: column;
            flex: 1;
        }}
        
        .option-method {{
            font-weight: 600;
            font-size: 13px;
        }}
        
        .option-description {{
            font-size: 12px;
            color: #888;
            margin-top: 2px;
        }}
        
        .option:hover .option-description {{
            color: rgba(255, 255, 255, 0.8);
        }}
        
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #888;
            font-size: 12px;
        }}
        
        .action-buttons {{
            display: flex;
            gap: 10px;
            margin-top: 30px;
            justify-content: center;
        }}
        
        .btn {{
            padding: 12px 30px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
        }}
        
        .btn-primary {{
            background-color: #007bff;
            color: white;
        }}
        
        .btn-primary:hover {{
            background-color: #0056b3;
        }}
        
        .btn-secondary {{
            background-color: #6c757d;
            color: white;
        }}
        
        .btn-secondary:hover {{
            background-color: #545b62;
        }}
        
        .no-entities {{
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
            border: 1px solid #c3e6cb;
        }}
        
        @media print {{
            body {{
                background-color: white;
            }}
            .container {{
                box-shadow: none;
            }}
            .action-buttons {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ PII Detection & Safeguarding Report</h1>
            <div class="header-info">
                <div class="header-info-item">
                    <label>Filename:</label>
                    <span>{filename}</span>
                </div>
                <div class="header-info-item">
                    <label>Analysis Date:</label>
                    <span>{timestamp}</span>
                </div>
                <div class="header-info-item">
                    <label>File Type:</label>
                    <span>{Path(filename).suffix.upper()}</span>
                </div>
                <div class="header-info-item">
                    <label>Overall Risk:</label>
                    <span class="risk-badge risk-{overall_risk.lower()}">{overall_risk}</span>
                </div>
            </div>
        </div>
        
        <div class="summary-section">
            <h2>📊 Analysis Summary</h2>
            <div class="summary-stats">
                <div class="stat-item">
                    <div class="stat-label">Total PII Detected</div>
                    <div class="stat-value">{len(entities)}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">High Risk Items</div>
                    <div class="stat-value">{sum(1 for e in entities if e.get('risk_level') == 'HIGH')}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Medium Risk Items</div>
                    <div class="stat-value">{sum(1 for e in entities if e.get('risk_level') == 'MEDIUM')}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Low Risk Items</div>
                    <div class="stat-value">{sum(1 for e in entities if e.get('risk_level') == 'LOW')}</div>
                </div>
            </div>
        </div>
        
        <div class="entities-section">
            <h2>🔍 Detected Entities & Recommendations</h2>
            {"".join(self._generate_entity_html(entities)) if entities else '<div class="no-entities">✓ No sensitive data detected!</div>'}
        </div>
        
        <div class="footer">
            <p>This report was automatically generated by the Image Protection System.</p>
            <p>Please review all recommendations and approve safeguarding methods before proceeding.</p>
        </div>
    </div>
</body>
</html>
"""
            
            if output_path:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                logger.info(f"HTML report saved to {output_path}")
            
            return html_content
        
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def _generate_entity_html(self, entities: List[Dict[str, Any]]) -> List[str]:
        """
        Generate HTML for each entity
        
        Args:
            entities: List of detected entities
            
        Returns:
            List of HTML entity blocks
        """
        html_blocks = []
        
        for i, entity in enumerate(entities, 1):
            risk_class = f"risk-{entity.get('risk_level', 'MEDIUM').lower()}"
            
            # Build recommendations HTML
            recommendations_html = ""
            for rec in entity.get('recommendations', []):
                recommendations_html += f'<div class="recommendation-item">💡 {rec}</div>'
            
            # Build safeguard options HTML
            safeguard_html = ""
            for option in entity.get('safeguard_options', []):
                safeguard_html += f"""
                <label class="option">
                    <input type="radio" name="entity_{i}_safeguard" value="{option['method']}">
                    <div class="option-text">
                        <span class="option-method">{option['method'].upper()}</span>
                        <span class="option-description">{option['description']}</span>
                    </div>
                </label>
                """
            
            entity_html = f"""
            <div class="entity-item">
                <div class="entity-header">
                    <div class="entity-type">#{i}. {entity.get('display_name', entity.get('type', 'Unknown'))}</div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <span class="risk-badge {risk_class}">{entity.get('risk_level', 'MEDIUM')}</span>
                        <span class="entity-confidence">Confidence: {entity.get('confidence', 0)}</span>
                    </div>
                </div>
                
                <div class="entity-content">
                    <div class="entity-detail">
                        <div class="entity-detail-label">Entity Type</div>
                        <div class="entity-detail-value">{entity.get('type', 'Unknown')}</div>
                    </div>
                    <div class="entity-detail">
                        <div class="entity-detail-label">Detected Value</div>
                        <div class="entity-detail-value">{entity.get('value', 'Hidden')}</div>
                    </div>
                </div>
                
                <div class="recommendations" style="width: 100%; margin-top: 15px;">
                    <div class="recommendations-title">Why This Matters</div>
                    {recommendations_html}
                </div>
                
                <div class="safeguard-options">
                    <div class="safeguard-title">How to Safeguard</div>
                    {safeguard_html}
                </div>
            </div>
            """
            
            html_blocks.append(entity_html)
        
        return html_blocks
    
    def generate_pdf_report(self, file_path: str, filename: str, entities: List[Dict[str, Any]], 
                          overall_risk: str, output_path: str = None) -> str:
        """
        Generate PDF report with detected PII and recommendations
        
        Args:
            file_path: Path to analyzed file
            filename: Original filename
            entities: List of detected entities
            overall_risk: Overall risk level
            output_path: Path to save PDF
            
        Returns:
            Path to generated PDF
        """
        try:
            if not output_path:
                output_path = f'reports/{Path(filename).stem}_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            doc = SimpleDocTemplate(output_path, pagesize=letter,
                                   rightMargin=72, leftMargin=72,
                                   topMargin=72, bottomMargin=18)
            
            story = []
            
            # Title
            story.append(Paragraph("🛡️ PII Detection & Safeguarding Report", self.styles['CustomTitle']))
            story.append(Spacer(1, 0.3 * inch))
            
            # Header Info
            header_data = [
                ['Filename:', filename],
                ['Analysis Date:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ['File Type:', Path(filename).suffix.upper()],
                ['Overall Risk Level:', overall_risk]
            ]
            
            header_table = Table(header_data, colWidths=[2 * inch, 3.5 * inch])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            
            story.append(header_table)
            story.append(Spacer(1, 0.3 * inch))
            
            # Summary
            story.append(Paragraph("Summary", self.styles['SectionHeading']))
            
            summary_data = [
                ['Total PII Detected', 'High Risk', 'Medium Risk', 'Low Risk'],
                [str(len(entities)), 
                 str(sum(1 for e in entities if e.get('risk_level') == 'HIGH')),
                 str(sum(1 for e in entities if e.get('risk_level') == 'MEDIUM')),
                 str(sum(1 for e in entities if e.get('risk_level') == 'LOW'))]
            ]
            
            summary_table = Table(summary_data, colWidths=[1.5 * inch] * 4)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 0.3 * inch))
            
            # Entities
            if entities:
                story.append(Paragraph("Detected Entities & Recommendations", self.styles['SectionHeading']))
                
                for i, entity in enumerate(entities, 1):
                    # Entity info
                    entity_table_data = [
                        [f"Entity #{i}: {entity.get('display_name', 'Unknown')}", 
                         f"Risk: {entity.get('risk_level', 'MEDIUM')}"],
                        ['Type:', entity.get('type', 'Unknown')],
                        ['Value:', entity.get('value', 'Hidden')],
                        ['Confidence:', str(entity.get('confidence', 0))]
                    ]
                    
                    entity_table = Table(entity_table_data, colWidths=[3.5 * inch, 2 * inch])
                    entity_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
                    ]))
                    
                    story.append(entity_table)
                    
                    # Recommendations
                    if entity.get('recommendations'):
                        rec_html = '<br/>'.join([f"• {rec}" for rec in entity.get('recommendations', [])])
                        story.append(Paragraph(f"<b>Recommendations:</b> {rec_html}", self.styles['Normal']))
                    
                    story.append(Spacer(1, 0.15 * inch))
                    
                    # Page break after every 3 entities
                    if i % 3 == 0:
                        story.append(PageBreak())
            else:
                story.append(Paragraph("✓ No sensitive data detected in this document.", self.styles['Normal']))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report saved to {output_path}")
            
            return output_path
        
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def generate_json_report(self, file_path: str, filename: str, entities: List[Dict[str, Any]], 
                            overall_risk: str, output_path: str = None) -> Dict[str, Any]:
        """
        Generate JSON report for programmatic access
        
        Args:
            file_path: Path to analyzed file
            filename: Original filename
            entities: List of detected entities
            overall_risk: Overall risk level
            output_path: Optional path to save JSON
            
        Returns:
            Report dictionary
        """
        report = {
            'report_type': 'pii_detection',
            'timestamp': datetime.now().isoformat(),
            'file_info': {
                'filename': filename,
                'file_path': str(file_path),
                'file_size': Path(file_path).stat().st_size if Path(file_path).exists() else 0
            },
            'summary': {
                'overall_risk': overall_risk,
                'total_entities': len(entities),
                'high_risk_count': sum(1 for e in entities if e.get('risk_level') == 'HIGH'),
                'medium_risk_count': sum(1 for e in entities if e.get('risk_level') == 'MEDIUM'),
                'low_risk_count': sum(1 for e in entities if e.get('risk_level') == 'LOW')
            },
            'entities': entities
        }
        
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logger.info(f"JSON report saved to {output_path}")
        
        return report
