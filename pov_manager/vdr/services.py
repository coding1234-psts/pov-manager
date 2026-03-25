import boto3
import json
import logging

from django.conf import settings
from django.utils import timezone

from vdr.models import DmarcScanResult, ThreatProfile

logger = logging.getLogger(__name__)

class DmarcScanService:
    """Service to handle DMARC scanning via AWS Lambda"""

    def __init__(self, lambda_function_name=None, region=None):
        self.lambda_function_name = lambda_function_name or settings.DMARC_LAMBDA_FUNCTION_NAME
        self.region = region or settings.DMARC_LAMBDA_REGION

        aws_session = boto3.session.Session()
        self.lambda_client = aws_session.client(
            service_name='lambda',
            region_name=self.region
        )

    def scan_domain(self, domain):
        """
        Invoke Lambda function to scan a domain

        Args:
            domain (str): The domain to scan

        Returns:
            dict: Scan results or error information
        """
        try:
            payload = json.dumps({'domain': domain})

            logger.info(f"Invoking Lambda for domain: {domain}")

            response = self.lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',  # Synchronous
                Payload=payload
            )

            # Parse response
            response_payload = json.loads(response['Payload'].read())

            if response_payload.get('statusCode') == 200:
                return {
                    'success': True,
                    'data': response_payload.get('body', {})
                }
            else:
                error = response_payload.get('body', {}).get('error', 'Unknown error')
                logger.error(f"Lambda returned error for {domain}: {error}")
                return {
                    'success': False,
                    'error': error
                }

        except Exception as e:
            logger.error(f"Failed to scan domain {domain}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def update_or_create_scan_result(self, threat_profile, domain):
        """
        Scan a domain and update/create the DmarcScanResult

        Args:
            threat_profile: Threat Profile instance
            domain (str): Domain to scan

        Returns:
            DmarcScanResult: The created or updated result
        """
        # Get or create the result object
        result, created = DmarcScanResult.objects.get_or_create(
            threat_profile=threat_profile,
            domain=domain,
            defaults={'scan_status': 'pending'}
        )

        # Update status to pending
        result.scan_status = 'pending'
        result.save(update_fields=['scan_status', 'updated_at'])

        # Perform the scan
        scan_response = self.scan_domain(domain)

        if scan_response['success']:
            data = scan_response['data']
            categories = data.get('categories', {})

            # Update the result with scan data
            result.overall_score = data.get('overall_score')
            result.headline = data.get('headline')
            result.summary = data.get('summary')

            # Category scores
            result.impersonation_score = categories.get('impersonation', {}).get('score')
            result.privacy_score = categories.get('privacy', {}).get('score')
            result.branding_score = categories.get('branding', {}).get('score')

            # Detailed protocols
            result.impersonation_protocols = categories.get('impersonation', {}).get('protocols', {})
            result.privacy_protocols = categories.get('privacy', {}).get('protocols', {})
            result.branding_protocols = categories.get('branding', {}).get('protocols', {})

            result.scan_status = 'success'
            result.error_message = None
            result.last_scanned_at = timezone.now()

            logger.info(f"Successfully scanned domain: {domain}")
        else:
            result.scan_status = 'failed'
            result.error_message = scan_response['error']
            logger.error(f"Failed to scan domain: {domain} - {scan_response['error']}")

        result.save()
        return result

    def scan_threat_profile_domains(self, threat_profile):
        """
        Scan all domains for a profile

        Args:
            threat_profile: Threat Profile instance

        Returns:
            list: List of DmarcScanResult objects
        """
        results = []
        domains = threat_profile.organization_email_domains or []

        # Remove None, empty strings, and duplicates
        domains = list(set([d.strip() for d in domains if d and d.strip()]))

        logger.info(f"Scanning {len(domains)} domains for threat profile {threat_profile.id}")

        for domain in domains:
            try:
                result = self.update_or_create_scan_result(threat_profile, domain)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning domain {domain} for threat profile {threat_profile.id}: {str(e)}")

        # Remove results for domains no longer in the list
        DmarcScanResult.objects.filter(threat_profile=threat_profile).exclude(domain__in=domains).delete()

        return results