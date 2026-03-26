from django.urls import path

from .views import (
    threat_profile,
    update_threat_profile,
    delete_threat_profile,
    start_vdr_scans,
    download_ctu_autobrief_zip_file,
    force_generate_ctu_autobrief_report,
    check_vivun_activity,
    export_threat_profiles_csv,
    cleanup_vdr_profile,
    get_se_emails_list,
    run_ai_exposure_scan_for_profile,
    download_ai_exposure_artifact,
)

urlpatterns = [
    path('threat-profile/',
         threat_profile,
         name='threat_profile'),

    path('threat-profile/<str:threat_profile_unique_id>/start_scans',
         start_vdr_scans,
         name='start_vdr_scans'),

    path('threat-profile/<str:threat_profile_unique_id>',
         update_threat_profile,
         name='update_threat_profile'),

    path('threat-profile/<str:threat_profile_unique_id>/delete',
         delete_threat_profile,
         name='delete_threat_profile'),

    path(
        'threat-profile/ctu_autobrief_zip/<str:ctu_autobrief_report_id>',
        download_ctu_autobrief_zip_file,
        name='ctu_autobrief_zip_file'),

    path(
        'threat-profile/<uuid:threat_profile_unique_id>/ai-exposure-scan/',
        run_ai_exposure_scan_for_profile,
        name='run_ai_exposure_scan',
    ),
    path(
        'threat-profile/ai-exposure-download/<str:file_basename>',
        download_ai_exposure_artifact,
        name='download_ai_exposure_report',
    ),

    path(
        'threat-profile/<str:threat_profile_unique_id>/force-generate-report/',
        force_generate_ctu_autobrief_report,
        name='force_generate_ctu_autobrief_report'
    ),

    path(
        'threat-profile/export/csv/',
        export_threat_profiles_csv,
        name='export_threat_profiles_csv'
    ),

    path('threat-profile/check-vivun-activity/',
         check_vivun_activity,
         name='check_vivun_activity'),

    path('threat-profile/<str:threat_profile_unique_id>/cleanup_vdr',
         cleanup_vdr_profile,
         name='cleanup_vdr_profile'),

    path('threat-profile/se-emails/',
         get_se_emails_list,
         name='get_se_emails_list'),
]
