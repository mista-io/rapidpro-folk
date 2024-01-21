"""
Written by Keeya Emmanuel Lubowa
On 24th Aug, 2022
Email ekeeya@oddjobs.tech
"""
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from smartmin.views import SmartCRUDL, SmartCreateView, SmartListView, SmartUpdateView, SmartView, SmartReadView, \
    SmartTemplateView
from .models import Handler
from .forms import HandlerForm

# Create your views here.
from .utils import ussd_logger, sanitize_shortcode
from ..orgs.views import OrgPermsMixin, ModalMixin, MenuMixin

from ..utils.views import SpaMixin, ContentMenuMixin
from django.http import HttpResponse


class HandlerCRUDL(SmartCRUDL):
    model = Handler
    path = "ussd/handlers"
    
    

    actions = (
        "list",
        "create",
        "delete",
        "read",
        # "update"
    )
    

    class Create(SpaMixin, ModalMixin, OrgPermsMixin, SmartCreateView):
        form_class = HandlerForm
        success_message = ""
        success_url = "@ussd.handler_list"
        submit_button_name = _("Create Handler")
        permission= "tickets.ticket_menu"

        def pre_save(self, obj):
            obj = super().pre_save(obj)
            obj.short_code = sanitize_shortcode(obj.short_code)
            return obj

        def get_form_kwargs(self):
            kwargs = super().get_form_kwargs()
            kwargs["org"] = self.request.org
          
            return kwargs

        def derive_title(self):
            return _("Configure your USSD Aggregator Handler")

    class Update(ModalMixin, OrgPermsMixin, SmartUpdateView):
        form_class = HandlerForm
        success_message = ""
        submit_button_name = _("Update Handler")
        model = Handler
        
        permission= "tickets.ticket_menu"

        def get_form_kwargs(self):
            kwargs = super().get_form_kwargs()
            kwargs["org"] = self.request.org
            return kwargs

        def get_form_kwargs(self):
            kwargs = super().get_form_kwargs()
            kwargs["org"] = self.request.org
            return kwargs
        

     
        

    class Read(SpaMixin, OrgPermsMixin, SmartReadView, ContentMenuMixin):
        # template_name = "ussd/handler_config.haml"

        def get_queryset(self):
            return Handler.objects.filter(is_active=True)

        def build_content_menu(self, menu):
            menu.add_modax(
                _("Edit"),
                "edit-handler",
                f"{reverse('ussd.handler_update', args=[self.object.pk])}",
                title=_("Edit Handler"),
            )

    class List(OrgPermsMixin, SmartListView, ContentMenuMixin):
        template_name = "ussd/handlers_list.html"
        search_fields = ['aggregator', 'short_code']
        title = _("Aggregator Handlers")
        bulk_actions = ("archive", "delete")
        permission= "tickets.ticket_menu"
        model = Handler


        def get_context_data(self, **kwargs):
            context = super().get_context_data(**kwargs)
            context['org_has_handlers'] = context['paginator'].count > 0
            context['actions'] = ("disable", "enable")
            return context

        
    # class Delete(OrgPermsMixin, SmartDeleteView):  # Change SmartView to SmartDeleteView
    #     success_message = ""
    #     submit_button_name = _("Delete Handler")

    #     def get(self, request, *args, **kwargs):
    #         handler = self.get_object()
    #         handler.is_active = False  # Assuming you have an 'is_active' field
    #         handler.save()
    #         return HttpResponse("Handler deleted successfully")  # Adjust response as need

def hello(Request):
    a=10
    return HttpResponse("Hello, world. You're at the polls index.")
    
    