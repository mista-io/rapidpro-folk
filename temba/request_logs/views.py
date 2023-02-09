from smartmin.views import SmartCRUDL, SmartListView, SmartReadView, smart_url

from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _

from temba.classifiers.models import Classifier
from temba.orgs.views import OrgObjPermsMixin, OrgPermsMixin
from temba.tickets.models import Ticketer
from temba.utils.views import ContentMenuMixin, SpaMixin

from .models import HTTPLog


class BaseObjLogsView(SpaMixin, OrgObjPermsMixin, SmartListView):
    """
    Base list view for logs associated with an object (e.g. ticketer, classifier)
    """

    paginate_by = 50
    permission = "request_logs.httplog_list"
    default_order = ("-created_on",)
    template_name = "request_logs/httplog_list.html"
    source_field = None
    source_url = None

    @classmethod
    def derive_url_pattern(cls, path, action):
        return r"^%s/%s/(?P<uuid>[^/]+)/$" % (path, action)

    def get_object_org(self):
        return self.source.org

    @cached_property
    def source(self):
        return get_object_or_404(self.get_source(self.kwargs["uuid"]))

    def get_source(self, uuid):  # pragma: no cover
        pass

    def get_queryset(self, **kwargs):
        return super().get_queryset(**kwargs).filter(**{self.source_field: self.source})

    def derive_select_related(self):
        return (self.source_field,)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["source"] = self.source
        context["source_url"] = smart_url(self.source_url, self.source)
        return context


class HTTPLogCRUDL(SmartCRUDL):
    model = HTTPLog
    actions = ("webhooks", "classifier", "ticketer", "read")

    class Webhooks(ContentMenuMixin, OrgPermsMixin, SmartListView):
        title = _("Webhook Calls")
        default_order = ("-created_on",)
        select_related = ("flow",)
        fields = ("flow", "url", "status_code", "request_time", "created_on")

        def build_content_menu(self, menu):
            menu.add_link(_("Flows"), reverse("flows.flow_list"))

        def get_queryset(self, **kwargs):
            return super().get_queryset(**kwargs).filter(org=self.request.org, flow__isnull=False)

    class Classifier(BaseObjLogsView):
        source_field = "classifier"
        source_url = "uuid@classifiers.classifier_read"
        title = _("Recent Classifier Events")

        def derive_menu_path(self):
            return f"/settings/classifiers/{self.source.uuid}"

        def get_source(self, uuid):
            return Classifier.objects.filter(uuid=uuid, is_active=True)

    class Ticketer(BaseObjLogsView):
        source_field = "ticketer"
        source_url = "@tickets.ticket_list"
        title = _("Recent Ticketing Service Events")

        def get_source(self, uuid):
            return Ticketer.objects.filter(uuid=uuid, is_active=True)

    class Read(SpaMixin, ContentMenuMixin, OrgObjPermsMixin, SmartReadView):
        fields = ("description", "created_on")

        @property
        def permission(self):
            return "request_logs.httplog_webhooks" if self.get_object().flow else "request_logs.httplog_read"

        def derive_menu_path(self):
            if self.get_object().classifier:
                return f"/settings/classifiers/{self.object.classifier.uuid}"
            return super().derive_menu_path()

        def build_content_menu(self, menu):
            object = self.get_object()
            if object and object.classifier:
                menu.add_link(
                    _("Classifier Log"), reverse("request_logs.httplog_classifier", args=[object.classifier.uuid])
                )
