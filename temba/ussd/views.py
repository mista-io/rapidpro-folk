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
from django.http import JsonResponse
from temba.orgs.models import Org,User


from .models import STARTS_WITH, ENDS_WITH, IS_IN_RESPONSE_BODY, IS_IN_HEADER_XML_JSON, IS_IN_HEADER_PLAIN_TEXT

STARTS_WITH = 1
ENDS_WITH = 2
IS_IN_RESPONSE_BODY = 3
IS_IN_HEADER_XML_JSON = 4
IS_IN_HEADER_PLAIN_TEXT = 5


class HandlerCRUDL(SmartCRUDL):
    model = Handler
    path = "ussd/handlers"
    permissions = True

    
    

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
        permission= "ussd.handler_create"


        def pre_save(self, obj):
            obj = super().pre_save(obj)
            obj.short_code = sanitize_shortcode(obj.short_code)
            org_id = self.request.org.id
            org_instance = Org.objects.get(id=org_id)
            obj.org_id = org_instance
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
        
        permission= "ussd.handler_update"

        def get_form_kwargs(self):
            kwargs = super().get_form_kwargs()
            kwargs["org"] = self.request.org
            
            return kwargs

        def get_form_kwargs(self):
            kwargs = super().get_form_kwargs()
            kwargs["org"] = self.request.org
            org_id = self.request.org.id
            print("##################### org ID", kwargs)
            print("##################### org ID2", org_id)
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
        permission= "ussd.handler_list"
        model = Handler

        def get_queryset(self):
            # Get the current organization ID
            org_id = self.request.org.id
            # Filter Handler objects based on the current organization ID
            queryset = super().get_queryset().filter(org_id_id=13)
            return queryset



        def get_context_data(self, **kwargs):
            context = super().get_context_data(**kwargs)

            # Check if 'paginator' is present in the context and not None
            if 'paginator' in context and context['paginator'] is not None:
                paginator = context['paginator']
                # Check if the paginator has any objects
                context['org_has_handlers'] = paginator.count > 0
                # Set empty message if paginator has no objects
                if paginator.count == 0:
                    context['empty_message'] = _("No handlers have been configured yet")
            else:
                # If 'paginator' is not present or None, set 'org_has_handlers' to False
                context['org_has_handlers'] = False
                # Provide a default empty message
                context['empty_message'] = _("No handlers have been configured yet")

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

def hello(self):
    # session = self.get_object()

    # session_id=session.id,
    # org=session.org.name,
    # org_id=session.org_id,
    return HttpResponse("org_id")
    
def get_default_request_structure(request):
    aggregator = request.GET.get('aggregator', '')

    # Define the available choices for "Menu Type Flag Mode"
    SIGNAL_CHOICES = [
        (STARTS_WITH, _("Starts With (Plain Text)")),
        (ENDS_WITH, _("Ends With (Plain Text)")),
        (IS_IN_RESPONSE_BODY, _("Is In Response (XML/JSON)")),
        (IS_IN_HEADER_XML_JSON, _("Is in Headers (XML/JSON)")),
        (IS_IN_HEADER_PLAIN_TEXT, _("Is in Headers (Plain Text)")),
    ]

    aggregator_to_allowed_modes = {
        'MISTA': [IS_IN_RESPONSE_BODY],
        'AFRICAS_TALKING': [STARTS_WITH],
    }

    allowed_modes = aggregator_to_allowed_modes.get(aggregator, [])
    # Filter the SIGNAL_CHOICES based on allowed modes
    filtered_choices = [(key, label) for key, label in SIGNAL_CHOICES if key in allowed_modes]
    print("#################",filtered_choices)
    # Implement your logic to fetch the default structures based on the aggregator
    aggregator_to_default_structure = {
        'MISTA': {
            'default_request_structure': '{{short_code=serviceCode}},  {{session_id=sessionId}}, {{from=msisdn}}, {{text=UserInput}}',
            'default_response_structure': '{{text=message}}, {{action=ContinueSession}}',

        },
        'AFRICAS_TALKING': {
            'default_request_structure': '{{short_code=serviceCode}},  {{session_id=sessionId}}, {{from=phoneNumber}}, {{text=text}}',
            'default_response_structure': '{{text=responseString}},  {{action=continueSession}}',
        },
    }

    default_structures = aggregator_to_default_structure.get(aggregator, {})
    response_data = {
        'signal_choices': filtered_choices,
        'default_structures': default_structures,
    }
    print(response_data)

    return JsonResponse(response_data)  