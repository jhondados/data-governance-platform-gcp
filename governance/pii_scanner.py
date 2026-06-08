"""Automated PII scanner using Cloud DLP."""
from google.cloud import dlp_v2
from google.cloud.dlp_v2.types import InspectContentRequest
from typing import List, Dict

INFO_TYPES = [
    "BRAZIL_CPF_NUMBER", "BRAZIL_RG_NUMBER", "EMAIL_ADDRESS",
    "PHONE_NUMBER", "DATE_OF_BIRTH", "PERSON_NAME",
    "STREET_ADDRESS", "CREDIT_CARD_NUMBER", "IBAN_CODE",
]

class PIIScanner:
    def __init__(self, project_id: str):
        self.client = dlp_v2.DlpServiceClient()
        self.parent = f"projects/{project_id}/locations/global"
        self.inspect_config = dlp_v2.InspectConfig(
            info_types=[dlp_v2.InfoType(name=t) for t in INFO_TYPES],
            min_likelihood=dlp_v2.Likelihood.LIKELY,
            include_quote=False,
        )

    def scan_text(self, text: str) -> Dict:
        request = dlp_v2.InspectContentRequest(
            parent=self.parent,
            inspect_config=self.inspect_config,
            item=dlp_v2.ContentItem(value=text),
        )
        response = self.client.inspect_content(request=request)
        findings = [{"info_type": f.info_type.name, "likelihood": f.likelihood.name}
                    for f in response.result.findings]
        return {"has_pii": len(findings) > 0, "findings": findings,
                "pii_types": list({f["info_type"] for f in findings})}

    def scan_bigquery_table(self, project: str, dataset: str, table: str) -> Dict:
        item = dlp_v2.BigQueryTable(project_id=project, dataset_id=dataset, table_id=table)
        request = dlp_v2.InspectContentRequest(
            parent=self.parent, inspect_config=self.inspect_config,
            item=dlp_v2.ContentItem(table=item))
        response = self.client.inspect_content(request=request)
        return {"table": f"{project}.{dataset}.{table}",
                "findings_count": len(response.result.findings),
                "has_sensitive_data": len(response.result.findings) > 0}
