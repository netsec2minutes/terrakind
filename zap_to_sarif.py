import json
import os

def convert_zap_json_to_sarif(json_report):
    sarif_report = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP ZAP",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    zap_report = json.loads(json_report)
    for alert in zap_report['alerts']:
        rule_id = alert['pluginid']
        sarif_report['runs'][0]['tool']['driver']['rules'].append({
            "id": rule_id,
            "name": alert['alert'],
            "shortDescription": {
                "text": alert['desc']
            },
            "helpUri": alert['reference']
        })

        sarif_report['runs'][0]['results'].append({
            "ruleId": rule_id,
            "level": "error",
            "message": {
                "text": alert['alert']
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": alert['url']
                        }
                    }
                }
            ]
        })

    return sarif_report

with open('report.json') as zap_report_file:
    zap_report = json.load(zap_report_file)

sarif_report = convert_zap_json_to_sarif(zap_report)

with open('./zap_report.sarif', 'w') as sarif_report_file:  # Guarantindo que o relatório SARIF seja salvo na raiz do repositório
    json.dump(sarif_report, sarif_report_file, indent=4)

print(os.path.abspath('./zap_report.sarif'))  # Imprimindo o caminho absoluto para o arquivo SARIF
