import json
from datetime import datetime

class JSONReport:
    """Handles reporting of results in JSON format."""
    def save_reports(self,results):
        "saves scan results to a JSON file"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scanner=results.get("scanner","unknown").lower()
        filename=f"reports/{scanner}_scan_report_{timestamp}.json"
        with open(filename,'w',encoding="utf-8") as f:
            json.dump(results,f,indent=4)