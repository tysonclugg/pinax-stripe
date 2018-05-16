import json
import logging

from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.utils.encoding import smart_str
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import (
    DetailView,
    FormView,
    ListView,
    TemplateView,
    View
)
from django.views.generic.edit import FormMixin

import stripe

from .actions import customers, events, exceptions, sources, subscriptions
from .conf import settings
from .forms import PaymentMethodForm, PlanForm
from .mixins import CustomerMixin, LoginRequiredMixin, PaymentsContextMixin
from .models import Card, Event, Invoice, Subscription

logger = logging.getLogger(__name__)


class VerificationError(stripe.error.SignatureVerificationError, SuspiciousOperation):
    """
    Stripe-Signature header validation failed.

    Inherits from SuspiciousOperation so that Django core middleware will return HttpResponseBadRequest (400), and from
    VerificationError since that's what we're wrapping.
    """
    pass


class InvoiceListView(LoginRequiredMixin, CustomerMixin, ListView):
    model = Invoice
    context_object_name = "invoice_list"
    template_name = "pinax/stripe/invoice_list.html"

    def get_queryset(self):
        return super(InvoiceListView, self).get_queryset().order_by("date")


class PaymentMethodListView(LoginRequiredMixin, CustomerMixin, ListView):
    model = Card
    context_object_name = "payment_method_list"
    template_name = "pinax/stripe/paymentmethod_list.html"

    def get_queryset(self):
        return super(PaymentMethodListView, self).get_queryset().order_by("created_at")


class PaymentMethodCreateView(LoginRequiredMixin, CustomerMixin, PaymentsContextMixin, TemplateView):
    model = Card
    template_name = "pinax/stripe/paymentmethod_create.html"

    def create_card(self, stripe_token):
        sources.create_card(self.customer, token=stripe_token)

    def post(self, request, *args, **kwargs):
        try:
            self.create_card(request.POST.get("stripeToken"))
            return redirect("pinax_stripe_payment_method_list")
        except stripe.CardError as e:
            return self.render_to_response(self.get_context_data(errors=smart_str(e)))


class PaymentMethodDeleteView(LoginRequiredMixin, CustomerMixin, DetailView):
    model = Card
    template_name = "pinax/stripe/paymentmethod_delete.html"

    def delete_card(self, stripe_id):
        sources.delete_card(self.customer, stripe_id)

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        try:
            self.delete_card(self.object.stripe_id)
            return redirect("pinax_stripe_payment_method_list")
        except stripe.CardError as e:
            return self.render_to_response(self.get_context_data(errors=smart_str(e)))


class PaymentMethodUpdateView(LoginRequiredMixin, CustomerMixin, PaymentsContextMixin, FormMixin, DetailView):
    model = Card
    form_class = PaymentMethodForm
    template_name = "pinax/stripe/paymentmethod_update.html"

    def update_card(self, exp_month, exp_year):
        sources.update_card(self.customer, self.object.stripe_id, exp_month=exp_month, exp_year=exp_year)

    def form_valid(self, form):
        try:
            self.update_card(form.cleaned_data["expMonth"], form.cleaned_data["expYear"])
            return redirect("pinax_stripe_payment_method_list")
        except stripe.CardError as e:
            return self.render_to_response(self.get_context_data(errors=smart_str(e)))

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


class SubscriptionListView(LoginRequiredMixin, CustomerMixin, ListView):
    model = Subscription
    context_object_name = "subscription_list"
    template_name = "pinax/stripe/subscription_list.html"

    def get_queryset(self):
        return super(SubscriptionListView, self).get_queryset().order_by("created_at")


class SubscriptionCreateView(LoginRequiredMixin, PaymentsContextMixin, CustomerMixin, FormView):
    template_name = "pinax/stripe/subscription_create.html"
    form_class = PlanForm

    @property
    def tax_percent(self):
        return settings.PINAX_STRIPE_SUBSCRIPTION_TAX_PERCENT

    def set_customer(self):
        if self.customer is None:
            self._customer = customers.create(self.request.user)

    def subscribe(self, customer, plan, token):
        subscriptions.create(customer, plan, token=token, tax_percent=self.tax_percent)

    def form_valid(self, form):
        self.set_customer()
        try:
            self.subscribe(self.customer, plan=form.cleaned_data["plan"], token=self.request.POST.get("stripeToken"))
            return redirect("pinax_stripe_subscription_list")
        except stripe.StripeError as e:
            return self.render_to_response(self.get_context_data(form=form, errors=smart_str(e)))


class SubscriptionDeleteView(LoginRequiredMixin, CustomerMixin, DetailView):
    model = Subscription
    template_name = "pinax/stripe/subscription_delete.html"

    def cancel(self):
        subscriptions.cancel(self.object)

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        try:
            self.cancel()
            return redirect("pinax_stripe_subscription_list")
        except stripe.StripeError as e:
            return self.render_to_response(self.get_context_data(errors=smart_str(e)))


class SubscriptionUpdateView(LoginRequiredMixin, CustomerMixin, FormMixin, DetailView):
    model = Subscription
    form_class = PlanForm
    template_name = "pinax/stripe/subscription_update.html"

    @property
    def current_plan(self):
        if not hasattr(self, "_current_plan"):
            self._current_plan = self.object.plan
        return self._current_plan

    def get_context_data(self, **kwargs):
        context = super(SubscriptionUpdateView, self).get_context_data(**kwargs)
        context.update({
            "form": self.get_form(form_class=self.form_class)
        })
        return context

    def update_subscription(self, plan_id):
        subscriptions.update(self.object, plan_id)

    def get_initial(self):
        initial = super(SubscriptionUpdateView, self).get_initial()
        initial.update({
            "plan": self.current_plan
        })
        return initial

    def form_valid(self, form):
        try:
            self.update_subscription(form.cleaned_data["plan"])
            return redirect("pinax_stripe_subscription_list")
        except stripe.StripeError as e:
            return self.render_to_response(self.get_context_data(form=form, errors=smart_str(e)))

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


class Webhook(View):

    secret = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(Webhook, self).dispatch(request, *args, **kwargs)

    def get_webhook_secret(self, request, data, *args, **kwargs):
        """
        Return the webhook secret for the given `request` and parsed `data`.

        You may override this method to return different secrets based upon
        request data such as `data["livemode"] == True` or similar.  The view
        `args` and `kwargs` are also passed in for inspection.

        You would want to override this if you wish to support rollover of the
        webhook secret without deploying new code, where you have chosen to
        store the secret in a database for example.
        """
        # secret provided via view kwargs or via settings
        return self.secret

    def post(self, request, *args, **kwargs):
        """
        Stripe webhook receiver.

        Raises VerificationError (a subclass of SuspiciousOperation) if there
        is a problem validating the Stripe-Signature header, and Stripe
        recieves a 400 (BAD REQUEST) status code.  We don't bother saving
        invalid webhook events, since we don't want to DoS either our database
        or the Stripe API if an attacker posts bogus webhook events.

        If Stripe doesn't get a response with status code of 2xx after a
        number of attempts, they will start sending alert emails to the Stripe
        account admins until the issue is resolved. Stripe will continue
        retrying webhook delivery for 3 days in live mode.

        Admins should be reviewing emails from Stripe and logs from Django
        daily as per section 10.6.1 of the Payment Card Industry (PCI) Data
        Security Standard (v3.2).  This means admins will have a day or two to
        resolve failed webhooks after they are notified via both emails from
        Stripe, and via errors logged from raising VerificationError.
        """
        body = smart_str(self.request.body)
        data = json.loads(body)
        valid = False

        if not settings.PINAX_STRIPE_WEBHOOK_VERIFY_SIGNATURES:
            # force fallback to verification via API calls
            logger.warn("PINAX_STRIPE_WEBHOOK_VERIFY_SIGNATURES disabled")
        else:
            try:
                sig_header = request.META["HTTP_STRIPE_SIGNATURE"]
            except KeyError:
                raise VerificationError("Missing Stripe-Signature header", sig_header=None)

            secret = self.get_webhook_secret(request, data, *args, **kwargs) or settings.PINAX_STRIPE_WEBHOOK_SECRET
            if not secret:
                raise ImproperlyConfigured("PINAX_STRIPE_WEBHOOK_SECRET not set")

            try:
                if not stripe.WebhookSignature.verify_header(
                    payload=request.body.decode("utf-8"),
                    header=sig_header,
                    secret=secret,
                    tolerance=settings.PINAX_STRIPE_WEBHOOK_TIMESTAMP_TOLERANCE,
                ):
                    raise VerificationError("Unverified webhook signature", sig_header=sig_header)
                valid = True
            except stripe.error.SignatureVerificationError as e:
                raise VerificationError("SignatureVerificationError: {}".format(e), sig_header=sig_header)

        event = Event.objects.filter(stripe_id=data["id"]).first()
        if event:
            exceptions.log_exception(body, "Duplicate event record", event=event)
        else:
            events.add_event(
                stripe_id=data["id"],
                kind=data["type"],
                livemode=data["livemode"],
                api_version=data["api_version"],
                message=data,
                valid=valid,
            )
        return HttpResponse(status=200)
