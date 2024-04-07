from django.contrib.auth.views import LoginView as BaseLoginView
from django.http import HttpResponseRedirect
from django.urls import reverse


class CustomLoginView(BaseLoginView):
    """
    Customized login view.

    """

    # make constructor to accept custom arguments

    def __init__(self, *args, **kwargs):
       # show message that it reached 
        print("CustomLoginView")
        super().__init__(*args, **kwargs)
 

    # Your custom view code here...
    def get_success_url(self):
        return reverse("your_redirect_url_name")