import json

class JSONReporter:
    """Handles reporting of results in JSON format."""
    def save_reports(self,results):
        "saves scan results to a JSON file"
        with open('scan_results.json','w') as f:
            json.dump(results,f,indent=4)
            