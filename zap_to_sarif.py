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

    return json.dumps(sarif_report)


if __name__ == "__main__":
    # Definindo o caminho absoluto para o relatório ZAP JSON
    zap_report_path = os.path.join(os.getenv('GITHUB_WORKSPACE', ''), 'report.json')

    with open(zap_report_path) as zap_report_file:
        zap_json_report = zap_report_file.read()
    
    sarif_report = convert_zap_json_to_sarif(zap_json_report)

    # Salvando o relatório SARIF na pasta raiz do repositório
    with open(os.path.join(os.getenv('GITHUB_WORKSPACE', ''), 'zap_report.sarif'), 'w') as sarif_report_file:
        sarif_report_file.write(sarif_report)
