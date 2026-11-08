class SecurityAnalysisFormatter:

    def format(self, analysis_result):
        lines = []

        # Header
        lines.append("========================================")
        lines.append("        SECURITY ANALYSIS REPORT")
        lines.append("========================================")

        # Overall Risk
        lines.append(
            f"Overall Risk: "
            f"{analysis_result.get('overall_risk', 'Info')}"
        )

        # Total Findings
        lines.append(
            f"Total Findings: "
            f"{analysis_result.get('total_findings', 0)}"
        )

        lines.append("")

        # Severity Summary
        lines.append("Severity Summary")
        lines.append("----------------")

        severity_summary = analysis_result.get(
            "severity_summary",
            {}
        )

        for severity in [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info"
        ]:
            lines.append(
                f"{severity}: "
                f"{severity_summary.get(severity, 0)}"
            )

        lines.append("")

        # Security Insights
        lines.append("Security Insights")
        lines.append("-----------------")

        insights = analysis_result.get(
            "insights",
            []
        )

        if not insights:
            lines.append(
                "No security insights generated."
            )

        for insight in insights:
            lines.append(
                f"[{insight.get('severity', 'Info')}] "
                f"{insight.get('title', 'Security Insight')}"
            )

            lines.append(
                f"Target: "
                f"{insight.get('target', 'Unknown')}"
            )

            lines.append(
                f"Type: "
                f"{insight.get('correlation_type', 'GENERAL')}"
            )

        lines.append("")

        # Recommendations
        lines.append("Recommendations")
        lines.append("----------------")

        recommendations = analysis_result.get(
            "recommendations",
            []
        )

        if not recommendations:
            lines.append(
                "No recommendations generated."
            )

        for recommendation in recommendations:
            lines.append(
                f"[{recommendation.get('severity', 'Info')}] "
                f"{recommendation.get('action', '')}"
            )

            lines.append(
                f"Target: "
                f"{recommendation.get('target', 'Unknown')}"
            )

        lines.append("")
        lines.append("========================================")

        # IMPORTANT:
        # This must be outside all loops.
        return "\n".join(lines)