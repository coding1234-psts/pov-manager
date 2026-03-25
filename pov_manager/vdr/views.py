# Standard Library Imports
import csv
import logging
import os

# Django Imports
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models.functions import Lower
from django.http import (
    FileResponse,
    HttpRequest,
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
    reverse
)

# Local Application Imports
from vdr.cache import (
    get_se_emails_from_cache,
    update_se_emails_cache_on_change,
    invalidate_se_emails_cache,
)
from vdr.ctuapi import submit_new_report as ctu_submit_new_report
from vdr.forms import ThreatProfileForm
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.vdrapi import (
    create_ip_range,
    create_tag,
    cleanup_tag_resources,
    VDRAPIError
)
from vdr.utils import generate_vulnerabilities_excel, validate_ip_range


logger = logging.getLogger(__name__)

ALLOWED_EXPORT_CSV_EMAILS = [
    'Alexandru.Pacuraru@sophos.com',
    'Andrew.Mundell@Sophos.com',
    'Paul.Talaba@sophos.com',
    'Ritesh.Singhai@sophos.com'
]

@login_required
def threat_profile(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = ThreatProfileForm(request.POST)
        if form.is_valid():
            try:
                se_email = form.data.get('se_email')
                ThreatProfile.objects.create(
                    organization_name=form.data.get('organization_name'),
                    organization_domain=form.data.get('organization_domain'),
                    se_email=se_email,
                    status=ThreatProfile.STATUS_CREATED,
                    vivun_activity=form.data.get('vivun_activity')
                ).save()

                new_profile = ThreatProfile.objects.get(organization_name=form.data.get('organization_name'))

                for email in form.data.getlist('organization_email_addresses'):
                    new_profile.organization_emails.append(email)

                for domain in form.data.getlist('organization_email_domains'):
                    new_profile.organization_email_domains.append(domain)

                if form.data.getlist('ip_ranges'):
                    ip_ranges = form.data.getlist('ip_ranges')
                    for ip_range in ip_ranges:
                        result = validate_ip_range(ip_range)
                        if not result['valid']:
                            if result['error'] == 'private':
                                error_message = 'Private IP ranges are not allowed.'
                            elif result['error'] == 'network':
                                error_message = f"IP address is not the network address. Use {result['correctNetwork']}"
                            else:
                                error_message = 'Invalid IP range format. Use format like 89.34.76.0/24.'

                            form.add_error('ip_ranges', error_message)
                            print(f'IP rage error for {ip_range}: {error_message}')
                            break
                            # TODO:Add return response with error
                    else:
                        # All valid, save ranges
                        for ip_range in ip_ranges:
                            new_profile.ip_ranges.append(ip_range)

                new_profile.created_by = request.user
                new_profile.save()
                
                # Update SE emails cache
                update_se_emails_cache_on_change(se_email)
            except Exception as e:
                print(f"Exception: {e}")

            return redirect(reverse('threat_profile') + '?created_by=on')

    # Retrieve filters from the request
    created_by_filter = request.GET.get('created_by') == 'on'
    se_email_filter = request.GET.get('se_email') == 'on'
    
    # Get multiple SE emails filter (comma-separated, normalized to lowercase)
    se_emails_filter = request.GET.get('se_emails', '')
    selected_se_emails = [email.strip().lower() for email in se_emails_filter.split(',') if email.strip()]

    # Pagination parameters
    page = int(request.GET.get('page', '1'))
    page_size = int(request.GET.get('page_size', '20'))

    profiles = ThreatProfile.objects.all()

    # Apply created_by filter if needed
    if created_by_filter:
        profiles = profiles.filter(created_by=request.user)
    
    # Apply SE email filters (case-insensitive)
    # Priority: selected_se_emails (multi-select) > se_email_filter (current user toggle)
    if selected_se_emails:
        # Use Lower() for case-insensitive matching
        profiles = profiles.annotate(se_email_lower=Lower('se_email')).filter(se_email_lower__in=selected_se_emails)
    elif se_email_filter:
        profiles = profiles.filter(se_email__iexact=request.user.email)

    # Order by the latest profile first
    profiles = profiles.order_by("-id")

    # Count total profiles for pagination
    total_profiles = profiles.count()
    total_pages = (total_profiles + page_size - 1) // page_size if total_profiles > 0 else 1

    # Apply pagination
    start_index = (page - 1) * page_size
    end_index = start_index + page_size
    profiles = profiles[start_index:end_index]
    
    # Get SE emails list for filter dropdown (from cache)
    all_se_emails = get_se_emails_from_cache()

    context = {
        "title": "Threat Profile",
        "location": "threat_profile",
        "profiles": profiles,
        'allow_to_export_csv': request.user.email in ALLOWED_EXPORT_CSV_EMAILS,
        
        # Pagination context
        'total_profiles': total_profiles,
        'total_pages': total_pages,
        'current_page': page,
        'page_size': page_size,
        'has_previous': page > 1,
        'has_next': page < total_pages,
        
        # Filters for pagination links
        'created_by_filter': 'on' if created_by_filter else '',
        'se_email_filter': 'on' if se_email_filter else '',
        
        # SE Email multi-select filter
        'all_se_emails': all_se_emails,
        'selected_se_emails': selected_se_emails,
        'se_emails_filter': se_emails_filter,
    }

    return render(request, "vdr/threat_profile.html", context)


@login_required
def update_threat_profile(request: HttpRequest, threat_profile_unique_id: str) -> HttpResponse:
    if request.method == "POST":
        form = ThreatProfileForm(request.POST)
        if form.is_valid():
            profile = get_object_or_404(ThreatProfile, unique_id=threat_profile_unique_id)

            if profile.status != ThreatProfile.STATUS_CREATED:
                return HttpResponse(status=405, content="<h1>Not Allowed</h1>")

            profile.organization_name = form.cleaned_data.get('organization_name')
            profile.organization_domain = form.cleaned_data.get('organization_domain')
            
            new_se_email = form.cleaned_data.get('se_email')
            old_se_email = profile.se_email
            profile.se_email = new_se_email
            profile.vivun_activity = form.cleaned_data.get('vivun_activity')

            profile.organization_emails = []
            for email in form.data.getlist('organization_email_addresses'):
                profile.organization_emails.append(email)

            profile.organization_email_domains = []
            for domain in form.data.getlist('organization_email_domains'):
                profile.organization_email_domains.append(domain)

            profile.ip_ranges = []
            if form.data.getlist('ip_ranges'):
                ip_ranges = form.data.getlist('ip_ranges')
                for ip_range in ip_ranges:
                    result = validate_ip_range(ip_range)
                    if not result['valid']:
                        if result['error'] == 'private':
                            error_message = 'Private IP ranges are not allowed.'
                        elif result['error'] == 'network':
                            error_message = f"IP address is not the network address. Use {result['correctNetwork']}"
                        else:
                            error_message = 'Invalid IP range format. Use format like 89.34.76.0/24.'

                        form.add_error('ip_ranges', error_message)
                        print(f'IP rage error for {ip_range}: {error_message}')
                        break
                        # TODO:Add return response with error
                else:
                    # All valid, save ranges
                    for ip_range in ip_ranges:
                        profile.ip_ranges.append(ip_range)

            profile.save()
            
            # Update SE emails cache if the SE email changed
            if new_se_email != old_se_email:
                update_se_emails_cache_on_change(new_se_email)

            return redirect(reverse('threat_profile') + '?created_by=on')

    return HttpResponseNotFound("<h1>Page not found</h1>")


@login_required
def delete_threat_profile(request: HttpRequest, threat_profile_unique_id: str) -> HttpResponse:
    if request.method == "POST":
        profile = get_object_or_404(ThreatProfile, unique_id=threat_profile_unique_id)

        if profile.status != ThreatProfile.STATUS_CREATED:
            return HttpResponse(status=405, content="<h1>Not Allowed</h1>")

        profile.delete()
        
        # Invalidate SE emails cache (SE email might no longer be in use)
        invalidate_se_emails_cache()
        
        return redirect(reverse('threat_profile') + '?created_by=on')

    return HttpResponseNotFound("<h1>Page not found</h1>")


def create_tag_in_vdr(organization_name: str, prefix: str = "threat_profile") -> str:
    organization_name = organization_name.strip().replace(" ", "_")
    tag_name = f"{prefix}_{organization_name}"
    return create_tag(tag_name)


@login_required
def start_vdr_scans(request: HttpRequest, threat_profile_unique_id: str) -> HttpResponse:
    profile = get_object_or_404(ThreatProfile, unique_id=threat_profile_unique_id)

    # Check if we have a range of IPs that it can be scanned
    if not profile.ip_ranges:
        print('There is no IP range to scan')
        return redirect(reverse('threat_profile') + '?created_by=on')

    if not profile.tag_id:
        profile.tag_id = create_tag_in_vdr(profile.organization_name)
        profile.status = ThreatProfile.STATUS_TAG_CREATED
        profile.save()

    if profile.status == ThreatProfile.STATUS_TAG_CREATED:
        for ip_range in profile.ip_ranges:
            print(create_ip_range(iprange=ip_range, tag_id=profile.tag_id))

        profile.status = ThreatProfile.STATUS_SCANS_SCHEDULED
        profile.save()

    return redirect(reverse('threat_profile') + '?created_by=on')


@login_required
def download_ctu_autobrief_zip_file(
        request: HttpRequest,
        ctu_autobrief_report_id: str
) -> FileResponse | HttpResponseNotFound:
    file_path = os.path.join(settings.CTU_REPORTS_PATH, f"{ctu_autobrief_report_id}.zip")
    if os.path.isfile(file_path):
        return FileResponse(open(file_path, "rb"), as_attachment=True, filename=f"{ctu_autobrief_report_id}.zip")
    return HttpResponseNotFound("<h1>Page not found</h1>")


@login_required
def export_threat_profiles_csv(request):
    """
    Exports all threat profiles to a CSV file and returns the file as an HTTP response.

    :param request: Django HTTP request
    :return: HTTP response with the CSV file
    """

    if request.user.email not in ALLOWED_EXPORT_CSV_EMAILS:
        return HttpResponseForbidden(
            "You don't have permission to perform this action."
        )

    # Fetch all threat profiles
    threat_profiles = ThreatProfile.objects.all().select_related('created_by')

    # Create the HTTP response with CSV content type
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threat_profiles.csv"'

    # Create CSV writer
    writer = csv.writer(response)

    # Write header row
    writer.writerow([
        'Organization Name',
        'Organization Domain',
        'Organization Email Domains',
        'Organization Emails',
        'IP Ranges',
        'SE Email',
        'VDR Tag ID',
        'Status',
        'Vivun Activity',
        'Created By',
        'Created Date',
        'Modified Date'
    ])

    # Write data rows
    for profile in threat_profiles:
        writer.writerow([
            profile.organization_name,
            profile.organization_domain or '',
            ', '.join(profile.organization_email_domains) if profile.organization_email_domains else '',
            ', '.join(profile.organization_emails) if profile.organization_emails else '',
            ', '.join(profile.ip_ranges) if profile.ip_ranges else '',
            profile.se_email or '',
            profile.tag_id or '',
            profile.get_status_display(),
            profile.vivun_activity,
            profile.created_by.email if profile.created_by else '',
            profile.created_date.strftime('%Y-%m-%d %H:%M:%S') if profile.created_date else '',
            profile.modified_data.strftime('%Y-%m-%d %H:%M:%S') if profile.modified_data else ''
        ])

    return response


@login_required
def force_generate_ctu_autobrief_report(request, threat_profile_unique_id):
    # Validate that the threat profile exists
    profile = get_object_or_404(ThreatProfile, unique_id=threat_profile_unique_id)

    data = {
        'client_name': profile.organization_name,
        'cached_domains': True,
        'domains': [profile.organization_domain],
        'email_domains': profile.organization_email_domains,
        'email_report': False,
        'exec_emails': profile.organization_emails,
        'keywords': [profile.organization_name],
        'manual_emails': [],
        'network_ranges': profile.ip_ranges,
        'search_vt': False,
        'shodan_filters': False,
        'take_domain_screenshots': True,
        'template': 'EBS_AutoSample_v0.4.docx',
        'template_pptx': 'Threat_Profile_DMARC_Template.pptx',
    }

    profile.ctu_autobrief_report_id = ctu_submit_new_report(data)
    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR
    profile.save()

    return redirect(reverse('threat_profile') + '?created_by=on')


def check_vivun_activity(request):
    # Ensure the request method is GET
    if request.method == 'GET':
        vivun_activity = request.GET.get('vivun_activity', '').strip()
        threat_profile_unique_id = request.GET.get('threat_profile_unique_id', None)

        # Ensure that the vivun_activity is valid
        if vivun_activity == '000000':
            return JsonResponse({'valid': True})  # 000000 is allowed

        # If threat_profile_unique_id is provided (in the case of editing
        # an existing profile),exclude it from the check
        if threat_profile_unique_id:
            if ThreatProfile.objects.filter(vivun_activity=vivun_activity).exclude(
                    unique_id=threat_profile_unique_id).exists():
                return JsonResponse({'valid': False, 'message': 'This Vivun Activity ID is already taken.'})
        else:
            # If no profile_id is provided, it’s a new profile, so just check for any duplicates
            if ThreatProfile.objects.filter(vivun_activity=vivun_activity).exists():
                return JsonResponse({'valid': False, 'message': 'This Vivun Activity ID is already taken.'})

        # If the vivun_activity does not exist for another profile, return valid
        return JsonResponse({'valid': True})

    # If the method is not GET, return a 405 Method Not Allowed
    return JsonResponse({'valid': False, 'message': 'Invalid request method.'}, status=405)


@login_required
def cleanup_vdr_profile(request: HttpRequest, threat_profile_unique_id: str) -> HttpResponse:
    """
    Clean up all VDR resources associated with a threat profile
    Deletes ranges, servers, websites, and the tag from VDR
    """
    profile = get_object_or_404(ThreatProfile, unique_id=threat_profile_unique_id)

    # TODO: Delete archive file

    if profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR:
        profile.tag_id = None
        profile.status = ThreatProfile.STATUS_CREATED
        profile.save()

        logger.info(f"Reset profile {profile.unique_id} without VDR cleanup.")

    elif profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE:
        try:
            # Clean up all VDR resources and delete the tag
            results = cleanup_tag_resources(tag_id=profile.tag_id, delete_tag_after=True)

            # Log the cleanup results
            logger.info(
                f"VDR cleanup completed for profile {profile.unique_id}: "
                f"{results['ranges_deleted']} ranges, "
                f"{results['servers_deleted']} servers, "
                f"{results['websites_deleted']} websites deleted, "
                f"tag deleted: {results['tag_deleted']}"
            )

            # Update profile status and clear tag_id
            profile.tag_id = None
            profile.status = ThreatProfile.STATUS_CREATED
            profile.save()

        except VDRAPIError as e:
            logger.error(f"Failed to cleanup VDR resources for profile {profile.unique_id}: {e}")

        except Exception as e:
            logger.error(f"Unexpected error during VDR cleanup for profile {profile.unique_id}: {e}")


    return redirect(reverse('threat_profile') + '?created_by=on')


@login_required
def get_se_emails_list(request: HttpRequest) -> JsonResponse:
    """
    API endpoint to get the list of unique SE emails for the filter dropdown.
    Returns a JSON response with the list of SE emails.
    """
    if request.method == 'GET':
        se_emails = get_se_emails_from_cache()
        return JsonResponse({
            'success': True,
            'se_emails': se_emails,
            'count': len(se_emails)
        })
    
    return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=405)
