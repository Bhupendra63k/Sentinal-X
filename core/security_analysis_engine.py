class SecurityAnalysisEngine:

    SEVERITY_PRIORITY={
        "Critical":5,
        "High":4,
        "Medium":3,
        "Low":2,
        "Info":1
    }
    def analyze(self,findings):
        if findings is None:
            findings=[]
        prioritized_findings=self.prioritize(findings)
        severity_summary=self.severity_summary(findings)
        overall_risk=self.overall_risk(findings)
        correlations=self.correlate(findings)
        insights=self.generate_insights(findings,correlations)
        recommendations=self.generate_recommendations(insights)

        return {
                "total_findings": len(findings),
                "severity_summary":severity_summary,
                "prioritized_findings":prioritized_findings,
                "overall_risk":overall_risk,
                "correlations":correlations,
                "insights":insights,
                "recommendations":recommendations,
                "findings": findings
            }

    def prioritize(self,findings):
        return sorted(findings,key=lambda finding:self.SEVERITY_PRIORITY.get(finding.get("severity","Info").capitalize(),1),reverse=True)

    def severity_summary(self,findings):
        summary={
            "Critical":0,
            "High":0,
            "Medium":0,
            "Low":0,
            "Info":0
        }

        for finding in findings:
            severity=finding.get("severity","Info").capitalize()
            if severity not in summary:
                severity="Info"
            summary[severity]+=1
        return summary

    def overall_risk(self,findings):
        if not findings:
            return "Info"
        for severity in ["Critical","High","Medium","Low","Info"]:
            for finding in findings:
                finding_severity=finding.get("severity","Info").capitalize()
                if finding_severity==severity:
                    return severity
        return "Info"

    def correlate(self,findings):
        correlations=[]
        targets={}
        for finding in findings:
            target=finding.get("target")
            if target not in targets:
                targets[target]=[]
            targets[target].append(finding)
        for target,target_findings in targets.items():
            scanners=set(finding.get("scanner") for finding in target_findings)
            if len(scanners)>1:
                correlations.append({
                    "target":target,
                    "finding_count":len(target_findings),
                    "scanners":list(scanners),
                    "finding_ids":[
                        finding.get("finding_id") for finding in target_findings
                    ],
                    "correlation_type":self.classify_correlation(target_findings),
                    "correlation_risk":self.correlation_risk(target_findings)
                })
        return correlations

    def classify_correlation(self,findings):
        text=""
        for finding in findings:
            text+=" ".join([
                str(finding.get("title","")),
                str(finding.get("description","")),
                str(finding.get("evidence","")),
                str(finding.get("service",""))
            ]).lower()
        web_keywords=["http","https","web","apache","nginx","iis","web server","web application"]
        for keyword in web_keywords:
            if keyword in text:
                return "WEB_ATTACK_SURFACE"
        return "GENERAL"

    def correlation_risk(self,findings):
        if not findings:
            return "Info"
        for severity in ["Critical","High","Medium","Low","Info"]:
            for finding in findings:
                finding_severity=finding.get("severity","Info").capitalize()
                if finding_severity==severity:
                    return severity
        return "Info"

    def generate_insights(self,findings,correlations):
        insights=[]
        for correlation in correlations:
            risk=correlation.get("correlation_risk","Info")
            if risk in ["High","Critical"]:
                insights.append({
                    "type":"SECURITY_INSIGHT",
                    "target":correlation.get("target"),
                    "severity":risk,
                    "title": "Multiple security findings detected",
                    "description":("Multiple scanners identified related security"
                                   "findings on the same target."),
                    "correlation_type":correlation.get("correlation_type","GENERAL"),
                    "finding_ids":correlation.get("finding_ids",[])

                })
        return insights
    def generate_recommendations(self,insights):
        recommendations=[]
        for insight in insights:
            severity=insight.get("severity","Info")
            if severity=="Critical":
                action=(
                    "Investigate the affected target immediately, "
                    "validate the findings, and prioritize remediation."
                )
            elif severity=="High":
                action=(
                    "Investigate the affected target and prioritize "
                    "remediation of the related findings."
                )
            else:
                action=(
                    "Review the related findings and address the "
                    "identified security issues."
                )
            recommendations.append({
                "target":insight.get("target"),
                "severity":severity,
                "type":"SECURITY_RECOMMENDATION",
                "action":action,
                "finding_ids":insight.get("finding_ids",[])
            })
        return recommendations
    