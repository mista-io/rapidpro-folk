import requests

from django.conf import settings
from django.forms import ValidationError
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from temba.channels.models import Channel
from temba.contacts.models import URN

from ...models import ChannelType, ConfigUI
from .views import SignalWireClaimView


class SignalWireType(ChannelType):
    """
    A SignalWire channel (https://signalwire.com)
    """

    code = "SW"
    name = "SignalWire"
    category = ChannelType.Category.PHONE

    courier_url = r"^sw/(?P<uuid>[a-z0-9\-]+)/(?P<action>receive)$"
    schemes = [URN.TEL_SCHEME]
    async_activation = False
    available_timezones = [
        "America/New_York",
        "America/Detroit",
        "America/Kentucky/Louisville",
        "America/Kentucky/Monticello",
        "America/Indiana/Indianapolis",
        "America/Indiana/Vincennes",
        "America/Indiana/Winamac",
        "America/Indiana/Marengo",
        "America/Indiana/Petersburg",
        "America/Indiana/Vevay",
        "America/Chicago",
        "America/Indiana/Tell_City",
        "America/Indiana/Knox",
        "America/Menominee",
        "America/North_Dakota/Center",
        "America/North_Dakota/New_Salem",
        "America/North_Dakota/Beulah",
        "America/Denver",
        "America/Boise",
        "America/Phoenix",
        "America/Los_Angeles",
        "America/Anchorage",
        "America/Juneau",
        "America/Sitka",
        "America/Metlakatla",
        "America/Yakutat",
        "America/Nome",
        "America/Adak",
        "Pacific/Honolulu",
        "US/Alaska",
        "US/Aleutian",
        "US/Arizona",
        "US/Central",
        "US/East-Indiana",
        "US/Eastern",
        "US/Hawaii",
        "US/Indiana-Starke",
        "US/Michigan",
        "US/Mountain",
        "US/Pacific",
    ]
    recommended_timezones = available_timezones

    claim_blurb = _("Easily add a two way number you have with %(link)s using their APIs.") % {
        "link": '<a target="_blank" href="http://www.signalwire.com/">SignalWire</a>'
    }
    claim_view = SignalWireClaimView

    config_ui = ConfigUI(
        blurb=_(
            "To finish configuring this channel, you may need to set this callback URL in your Signalwire account."
        ),
        endpoints=[
            ConfigUI.Endpoint(
                courier="receive",
                label=_("Inbound URL"),
                help=_("This endpoint will be called by SignalWire when new messages are received to your number."),
            ),
        ],
    )

    def deactivate(self, channel):
        pass

    def activate(self, channel):
        address = channel.address
        base_url = channel.config[Channel.CONFIG_BASE_URL]
        sid = channel.config[Channel.CONFIG_ACCOUNT_SID]
        token = channel.config[Channel.CONFIG_AUTH_TOKEN]
        callback_domain = channel.config[Channel.CONFIG_CALLBACK_DOMAIN]

        # try to list the API to find the number SID
        phone_sid = ""
        try:
            response = requests.get(
                f"{base_url}/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json", auth=(sid, token)
            )

            response.raise_for_status()
            response_json = response.json()

            for phone in response_json.get("incoming_phone_numbers", []):
                if phone.get("phone_number", "") == address:
                    phone_sid = phone.get("sid", "")
                    break

        except Exception:
            raise ValidationError("Unable to connect to SignalWire, please check your domain, key and token")

        if phone_sid == "":
            raise ValidationError(f"Unable to find number {address} on your account, please check and try again")

        channel_uuid = channel.uuid
        sms_url = "https://" + callback_domain + reverse("courier.sw", args=[channel_uuid, "receive"])
        status_url = "https://" + callback_domain + reverse("mailroom.ivr_handler", args=[channel_uuid, "status"])
        voice_url = "https://" + callback_domain + reverse("mailroom.ivr_handler", args=[channel_uuid, "incoming"])

        # register our callback URLs
        try:
            response = requests.post(
                f"{base_url}/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers/{phone_sid}.json",
                data=dict(
                    SmsUrl=sms_url,
                    SmsMethod="POST",
                    SmsFallbackUrl=sms_url,
                    SmsFallbackMethod="POST",
                    VoiceUrl=voice_url,
                    VoiceMethod="POST",
                    StatusCallback=status_url,
                    StatusCallbackMethod="POST",
                    VoiceFallbackUrl=f"{settings.STORAGE_URL}/voice_unavailable.xml",
                    VoiceFallbackMethod="GET",
                ),
                auth=(sid, token),
            )
            response.raise_for_status()

        except Exception:
            raise ValidationError(
                "Unable to update your phone number settings, please check your domain, key and token"
            )

    def get_error_ref_url(self, channel, code: str) -> str:
        return "https://developer.signalwire.com/compatibility-api/rest/overview/error-codes/"
