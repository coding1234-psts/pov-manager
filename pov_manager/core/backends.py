from django.contrib.auth import get_user_model
from microsoft_auth.backends import MicrosoftAuthenticationBackend


User = get_user_model()


class CustomMicrosoftBackend(MicrosoftAuthenticationBackend):

    def _verify_microsoft_user(self, microsoft_user, data):
        user = microsoft_user.user

        if user is None:
            fullname = data.get("name")
            first_name, last_name = "", ""
            if fullname:
                try:
                    last_name, first_name = fullname.split(", ")
                except ValueError:
                    try:
                        first_name, last_name = fullname.split(" ", 1)
                    except ValueError:
                        first_name = fullname

            try:
                user = User.objects.get(email=data["email"])
                if not user.first_name and not user.last_name:
                    user.first_name = first_name
                    user.last_name = last_name
                    user.save()
            except User.DoesNotExist:
                user = User(
                    email=data["email"],
                    first_name=first_name,
                    last_name=last_name,
                )
                user.save()

            existing_account = self._get_existing_microsoft_account(user)
            if existing_account:
                if self.config.MICROSOFT_AUTH_AUTO_REPLACE_ACCOUNTS:
                    existing_account.user = None
                    existing_account.save()
                else:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(
                        f"User {user.email} already has linked Microsoft account and "
                        "MICROSOFT_AUTH_AUTO_REPLACE_ACCOUNTS is False"
                    )
                    return None

            microsoft_user.user = user
            microsoft_user.save()

        return user
