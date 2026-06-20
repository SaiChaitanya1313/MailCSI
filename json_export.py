import json
from datetime import datetime


def export_json(result):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"phishscope_report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Saved JSON report: {filename}")