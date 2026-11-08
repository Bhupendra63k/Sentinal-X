import json
import os
from datetime import datetime

class JSONReport:
    """Handles reporting of results in JSON format."""
    def save_reports(self,results):
        "saves scan results to a JSON file"
        os.makedirs("reports",exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scanner=results.get("scanner","unknown").lower()
        filename=f"reports/{scanner}_scan_report_{timestamp}.json"
        with open(filename,'w',encoding="utf-8") as f:
            json.dump(results,f,indent=4)
        print(f"JSON report saved: {filename}")