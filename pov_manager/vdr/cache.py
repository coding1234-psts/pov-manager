"""
Cache utilities for VDR app.
Manages caching of SE emails for the threat profile filter.
"""
import logging
from django.conf import settings
from django.core.cache import cache

from vdr.models import ThreatProfile

logger = logging.getLogger(__name__)


def get_se_emails_from_cache():
    """
    Get the list of unique SE emails from cache.
    If not in cache, fetch from database and cache the result.
    
    Returns:
        list: Sorted list of unique SE email addresses
    """
    cache_key = getattr(settings, 'SE_EMAIL_CACHE_KEY', 'vdr_se_emails_list')
    cache_timeout = getattr(settings, 'SE_EMAIL_CACHE_TIMEOUT', 60 * 60 * 24)
    
    # Try to get from cache first
    se_emails = cache.get(cache_key)
    
    if se_emails is None:
        # Cache miss - fetch from database
        se_emails = refresh_se_emails_cache()
        logger.info(f"SE emails cache miss. Fetched {len(se_emails)} emails from database.")
    
    return se_emails


def refresh_se_emails_cache():
    """
    Refresh the SE emails cache by fetching all unique SE emails from the database.
    Normalizes emails to lowercase to avoid case-insensitive duplicates.
    
    Returns:
        list: Sorted list of unique SE email addresses (lowercase)
    """
    cache_key = getattr(settings, 'SE_EMAIL_CACHE_KEY', 'vdr_se_emails_list')
    cache_timeout = getattr(settings, 'SE_EMAIL_CACHE_TIMEOUT', 60 * 60 * 24)
    
    # Fetch SE emails from database, excluding null/empty values
    raw_emails = (
        ThreatProfile.objects
        .exclude(se_email__isnull=True)
        .exclude(se_email='')
        .values_list('se_email', flat=True)
    )
    
    # Normalize to lowercase and remove duplicates
    se_emails = sorted(set(email.lower().strip() for email in raw_emails))
    
    # Store in cache
    cache.set(cache_key, se_emails, cache_timeout)
    logger.debug(f"SE emails cache refreshed with {len(se_emails)} emails.")
    
    return se_emails


def invalidate_se_emails_cache():
    """
    Invalidate the SE emails cache.
    Call this when a threat profile is created, updated, or deleted.
    """
    cache_key = getattr(settings, 'SE_EMAIL_CACHE_KEY', 'vdr_se_emails_list')
    cache.delete(cache_key)
    logger.debug("SE emails cache invalidated.")


def update_se_emails_cache_on_change(se_email):
    """
    Efficiently update the cache when a new SE email is added.
    Instead of invalidating, we add the new email if it doesn't exist.
    Normalizes email to lowercase.
    
    Args:
        se_email: The SE email that was added/updated
    """
    if not se_email:
        return
    
    # Normalize to lowercase
    se_email = se_email.lower().strip()
    
    cache_key = getattr(settings, 'SE_EMAIL_CACHE_KEY', 'vdr_se_emails_list')
    cache_timeout = getattr(settings, 'SE_EMAIL_CACHE_TIMEOUT', 60 * 60 * 24)
    
    se_emails = cache.get(cache_key)
    
    if se_emails is None:
        # Cache doesn't exist, refresh it
        refresh_se_emails_cache()
    elif se_email not in se_emails:
        # Add new email and re-sort
        se_emails.append(se_email)
        se_emails.sort()
        cache.set(cache_key, se_emails, cache_timeout)
        logger.debug(f"Added {se_email} to SE emails cache.")

