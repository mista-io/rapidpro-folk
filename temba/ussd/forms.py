"""
Written by Keeya Emmanuel Lubowa
On 24th Aug, 2022.
Email ekeeya@oddjobs.tech
"""

from django import forms
from .models import Handler
from .models import Org
import socket

from ..utils.fields import InputWidget, SelectWidget, CompletionTextarea, CheckboxWidget

hostname = f"https://{socket.gethostname()}"

CONFIG_DEFAULT_REQUEST_STRUCTURE = (
    "{{short_code=serviceCode}},  {{session_id=sessionId}}, {{from=msisdn}}, {{text=UserInput}}"
)
CONFIG_DEFAULT_RESPONSE_STRUCTURE = (
    "{{text=message}}, {{action=ContinueSession}}"
)


class HandlerForm(forms.ModelForm):
    def __init__(self, org, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.org = org
        self.fields['response_structure'].required = False
        self.fields['request_structure'].initial = CONFIG_DEFAULT_REQUEST_STRUCTURE
        self.fields['response_structure'].initial = CONFIG_DEFAULT_RESPONSE_STRUCTURE
        # filter the channels to only show those that are for this org
        self.fields['channel'].queryset = self.fields['channel'].queryset.filter(org=self.org)
        # filter by external channel type for channel
        self.fields['channel'].queryset = self.fields['channel'].queryset.filter(channel_type="EX")

    
    class Meta:
        model = Handler
        exclude = ["is_active", "uuid","org_id"]
        widgets = {"short_code": InputWidget(),
                   "aggregator": SelectWidget(attrs={'onchange': 'updateStructures()', 'class': 'selected'}),
                   "channel": SelectWidget(),

                   "request_structure": CompletionTextarea( attrs={'style': 'display: none;'}),
                   "response_structure": CompletionTextarea( attrs={'style': 'display: none;'}),
                   "signal_exit_or_reply_mode": InputWidget(attrs={'style': 'display: none;'}),
                   "signal_menu_type_strings": InputWidget(attrs={'style': 'display: none;'}),
                #    "signal_exit_or_reply_mode": InputWidget(),
                #    "signal_menu_type_strings": InputWidget(),

                   "signal_header_key": InputWidget( attrs={'style': 'display: none;'}),
                   "trigger_word": InputWidget(),
                   "enable_repeat_current_step": CheckboxWidget(),
                   "auth_scheme": SelectWidget(attrs={'style': 'display: none;'}),
                   }
