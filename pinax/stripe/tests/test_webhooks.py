import decimal
import json
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.dispatch import Signal
from django.test import RequestFactory, TestCase, override_settings

import mock
import six
import stripe
from mock import patch

from . import (
    PLAN_CREATED_TEST_DATA,
    TRANSFER_CREATED_TEST_DATA,
    TRANSFER_PENDING_TEST_DATA
)
from ..models import (
    Account,
    Customer,
    Event,
    EventProcessingException,
    Plan,
    Transfer
)
from ..views import VerificationError
from ..views import Webhook as WebhookView
from ..webhooks import (
    AccountApplicationDeauthorizeWebhook,
    AccountExternalAccountCreatedWebhook,
    AccountUpdatedWebhook,
    ChargeCapturedWebhook,
    CustomerDeletedWebhook,
    CustomerSourceCreatedWebhook,
    CustomerSourceDeletedWebhook,
    CustomerSubscriptionCreatedWebhook,
    CustomerUpdatedWebhook,
    InvoiceCreatedWebhook,
    Webhook,
    registry
)

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse


class WebhookRegistryTest(TestCase):

    def test_get_signal(self):
        signal = registry.get_signal("account.updated")
        self.assertTrue(isinstance(signal, Signal))

    def test_get_signal_keyerror(self):
        self.assertIsNone(registry.get_signal("not a webhook"))


class WebhookTests(TestCase):

    event_data = {
        "api_version": "2017-06-05",
        "created": 1348360173,
        "data": {
            "object": {
                "amount": 455,
                "currency": "usd",
                "date": 1348876800,
                "description": None,
                "id": "ach_XXXXXXXXXXXX",
                "object": "transfer",
                "other_transfers": [],
                "status": "pending",
                "livemode": True,
                "reversed": False,
                "summary": {
                    "adjustment_count": 0,
                    "adjustment_fee_details": [],
                    "adjustment_fees": 0,
                    "adjustment_gross": 0,
                    "charge_count": 1,
                    "charge_fee_details": [{
                        "amount": 45,
                        "application": None,
                        "currency": "usd",
                        "description": None,
                        "type": "stripe_fee"
                    }],
                    "charge_fees": 45,
                    "charge_gross": 500,
                    "collected_fee_count": 0,
                    "collected_fee_gross": 0,
                    "currency": "usd",
                    "net": 455,
                    "refund_count": 0,
                    "refund_fees": 0,
                    "refund_gross": 0,
                    "validation_count": 0,
                    "validation_fees": 0
                }
            }
        },
        "id": "evt_XXXXXXXXXXXXx",
        "livemode": True,
        "object": "event",
        "pending_webhooks": 1,
        "type": "transfer.created"
    }

    def test_webhook_init(self):
        event = Event(kind=None)
        webhook = Webhook(event)
        self.assertIsNone(webhook.name)

    @patch("stripe.Event.retrieve")
    @patch("stripe.Transfer.retrieve")
    def test_webhook_with_transfer_event(self, TransferMock, StripeEventMock):
        StripeEventMock.return_value.to_dict.return_value = self.event_data
        TransferMock.return_value = self.event_data["data"]["object"]
        msg = json.dumps(self.event_data)
        resp = self.client.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json"
        )
        self.assertEquals(resp.status_code, 200)
        self.assertTrue(Event.objects.filter(kind="transfer.created").exists())

    @patch("stripe.Event.retrieve")
    @patch("stripe.Transfer.retrieve")
    def test_webhook_associated_with_stripe_account(self, TransferMock, StripeEventMock):
        connect_event_data = self.event_data.copy()
        account = Account.objects.create(stripe_id="acc_XXX")
        connect_event_data["account"] = account.stripe_id
        StripeEventMock.return_value.to_dict.return_value = connect_event_data
        TransferMock.return_value = connect_event_data["data"]["object"]
        msg = json.dumps(connect_event_data)
        resp = self.client.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json"
        )
        self.assertEquals(resp.status_code, 200)
        self.assertTrue(Event.objects.filter(kind="transfer.created").exists())
        self.assertEqual(
            Event.objects.filter(kind="transfer.created").first().stripe_account,
            account
        )
        self.assertEquals(TransferMock.call_args_list, [
            [("ach_XXXXXXXXXXXX",), {"stripe_account": "acc_XXX"}],
        ])

    def test_webhook_duplicate_event(self):
        data = {"id": 123}
        Event.objects.create(stripe_id=123, livemode=True)
        msg = json.dumps(data)
        resp = self.client.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json"
        )
        self.assertEquals(resp.status_code, 200)
        dupe_event_exception = EventProcessingException.objects.get()
        self.assertEqual(dupe_event_exception.message, "Duplicate event record")
        self.assertEqual(str(dupe_event_exception.data), '{"id": 123}')

    def test_webhook_event_mismatch(self):
        event = Event(kind="account.updated")
        WH = registry.get("account.application.deauthorized")
        with self.assertRaises(Exception):
            WH(event)

    @patch("django.dispatch.Signal.send")
    def test_send_signal(self, SignalSendMock):
        event = Event(kind="account.application.deauthorized")
        WH = registry.get("account.application.deauthorized")
        WH(event).send_signal()
        self.assertTrue(SignalSendMock.called)

    def test_send_signal_not_sent(self):
        event = Event(kind="account.application.deauthorized")
        WH = registry.get("account.application.deauthorized")

        def signal_handler(sender, *args, **kwargs):
            self.fail("Should not have been called.")
        registry.get_signal("account.application.deauthorized").connect(signal_handler)
        webhook = WH(event)
        webhook.name = "mismatch name"  # Not sure how this ever happens due to the registry
        webhook.send_signal()

    @patch("pinax.stripe.actions.customers.link_customer")
    @patch("pinax.stripe.webhooks.Webhook.validate")
    @patch("pinax.stripe.webhooks.Webhook.process_webhook")
    def test_process_exception_is_logged(self, ProcessWebhookMock, ValidateMock, LinkMock):
        # note: we choose an event type for which we do no processing
        event = Event.objects.create(kind="account.external_account.created", webhook_message={}, valid=True, processed=False)
        ProcessWebhookMock.side_effect = stripe.StripeError("Message", "error")
        with self.assertRaises(stripe.StripeError):
            AccountExternalAccountCreatedWebhook(event).process()
        self.assertTrue(EventProcessingException.objects.filter(event=event).exists())

    @patch("pinax.stripe.actions.customers.link_customer")
    @patch("pinax.stripe.webhooks.Webhook.validate")
    @patch("pinax.stripe.webhooks.Webhook.process_webhook")
    def test_process_exception_is_logged_non_stripeerror(self, ProcessWebhookMock, ValidateMock, LinkMock):
        # note: we choose an event type for which we do no processing
        event = Event.objects.create(kind="account.external_account.created", webhook_message={}, valid=True, processed=False)
        ProcessWebhookMock.side_effect = Exception("generic exception")
        with self.assertRaises(Exception):
            AccountExternalAccountCreatedWebhook(event).process()
        self.assertTrue(EventProcessingException.objects.filter(event=event).exists())

    @patch("pinax.stripe.actions.customers.link_customer")
    @patch("pinax.stripe.webhooks.Webhook.validate")
    def test_process_return_none(self, ValidateMock, LinkMock):
        # note: we choose an event type for which we do no processing
        event = Event.objects.create(kind="account.external_account.created", webhook_message={}, valid=True, processed=False)
        self.assertIsNone(AccountExternalAccountCreatedWebhook(event).process())


@override_settings(
    PINAX_STRIPE_WEBHOOK_VERIFY_SIGNATURES=True,
)
class WebhookVerificationTest(TestCase):

    event_data = {
        "api_version": "2017-06-05",
        "created": 1506381458,
        "data": {
            "object": {
                "id": "silver-express-898",
                "object": "plan",
                "amount": 999,
                "created": 1506381458,
                "currency": "usd",
                "interval": "month",
                "interval_count": 1,
                "livemode": False,
                "metadata": {},
                "name": "Silver Express",
                "statement_descriptor": None,
                "trial_period_days": None,
            },
        },
        "id": "evt_XXXXXXXXXXXXx",
        "livemode": True,
        "object": "event",
        "pending_webhooks": 1,
        "type": "plan.created"
    }
    stripe_data = {
        "/v1/events/evt_XXXXXXXXXXXXx": event_data,
    }

    def setUp(self):
        self.request_factory = RequestFactory()
        # mock the Stripe API for retrieving Event and Plan data
        self.stripe_object_request_mock = patch(
            "stripe.StripeObject.request",
            new=mock.MagicMock(
                side_effect=self.stripe_get,
            ),
        ).start()
        self.view_logger_warn_mock = patch("pinax.stripe.views.logger.warn").start()
        # unpatch all mocks when tests complete
        self.addCleanup(patch.stopall)

    def stripe_get(self, method, path):
        self.assertEqual(method, "get")
        return self.stripe_data[path]

    def post_webhook(self, *args, **kwargs):
        request = self.request_factory.post(*args, **kwargs)
        view = WebhookView.as_view()
        return view(request)

    @staticmethod
    def signature_headers(payload, secret=None, timestamp=None):
        if secret is None:
            secret = settings.PINAX_STRIPE_WEBHOOK_SECRET or "unobtainium"

        if timestamp is None:
            timestamp = int(time.time())  # seconds since epoch

        # sign payload with timestamp and then compute signature
        signed_payload = "{}.{}".format(timestamp, payload)
        signature = stripe.WebhookSignature._compute_signature(signed_payload, secret)

        # headers are CGI style: Stripe-Signature becomes HTTP_STRIPE_SIGNATURE
        return {
            "HTTP_STRIPE_SIGNATURE": "t={},v0=invalid,v1={}".format(int(timestamp), signature),
        }

    def test_webhook_secret_passed_via_as_view(self):
        # create view instance with secret
        view = WebhookView.as_view(secret="apples")

        # call webhook with a request
        msg = json.dumps(self.event_data)
        request = self.request_factory.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json",
            **self.signature_headers(msg, secret="apples")
        )
        resp = view(request)

        # confirm the event was accepted and processed
        self.assertEqual(resp.status_code, 200)
        self.stripe_object_request_mock.assert_not_called()  # no need to check with the Stripe API
        self.view_logger_warn_mock.assert_not_called()
        self.assertQuerysetEqual(EventProcessingException.objects.all(), [])
        self.assertQuerysetEqual(
            Event.objects.values_list("kind", "stripe_id", "valid", "processed"),
            [("plan.created", "evt_XXXXXXXXXXXXx", True, True)],
            transform=tuple,
        )

    def test_webhook_secret_via_get_webhook_secret(self):
        # subclass WebhookView custom get_webhook_secret implementation
        class CustomWebhookView(WebhookView):
            def get_webhook_secret(self, request, data, *args, **kwargs):
                if data["livemode"]:
                    return "whsec_apples"
                else:
                    return "whsec_bananas"

        view = CustomWebhookView.as_view()

        msg = json.dumps(self.event_data)
        request = self.request_factory.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json",
            **self.signature_headers(msg, secret="whsec_apples")
        )
        resp = view(request)

        # confirm the event was accepted and processed
        self.assertEqual(resp.status_code, 200)
        self.stripe_object_request_mock.assert_not_called()  # no need to check with the Stripe API
        self.view_logger_warn_mock.assert_not_called()
        self.assertQuerysetEqual(EventProcessingException.objects.all(), [])
        self.assertQuerysetEqual(
            Event.objects.values_list("kind", "stripe_id", "valid", "processed"),
            [("plan.created", "evt_XXXXXXXXXXXXx", True, True)],
            transform=tuple,
        )

    def test_correct_webhook_secret_returns_200(self):
        msg = json.dumps(self.event_data)
        resp = self.post_webhook(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json",
            **self.signature_headers(msg)
        )

        # confirm the event was accepted and processed
        self.assertEqual(resp.status_code, 200)
        self.stripe_object_request_mock.assert_not_called()  # no need to check with the Stripe API
        self.view_logger_warn_mock.assert_not_called()
        self.assertQuerysetEqual(EventProcessingException.objects.all(), [])
        self.assertQuerysetEqual(
            Event.objects.values_list("kind", "stripe_id", "valid", "processed"),
            [("plan.created", "evt_XXXXXXXXXXXXx", True, True)],
            transform=tuple,
        )

    @override_settings(
        PINAX_STRIPE_WEBHOOK_VERIFY_SIGNATURES=False,
    )
    def test_verify_disabled_returns_200(self):
        msg = json.dumps(self.event_data)
        resp = self.client.post(
            reverse("pinax_stripe_webhook"),
            six.u(msg),
            content_type="application/json",
            **self.signature_headers(msg)
        )

        # confirm the event was accepted and processed
        self.assertEqual(resp.status_code, 200)
        self.stripe_object_request_mock.assert_called_once_with("get", "/v1/events/evt_XXXXXXXXXXXXx")
        self.view_logger_warn_mock.assert_called_once_with("PINAX_STRIPE_WEBHOOK_VERIFY_SIGNATURES disabled")
        self.assertQuerysetEqual(EventProcessingException.objects.all(), [])
        self.assertQuerysetEqual(
            Event.objects.values_list("kind", "stripe_id", "valid", "processed"),
            [("plan.created", "evt_XXXXXXXXXXXXx", True, True)],
            transform=tuple,
        )

    @override_settings(
        PINAX_STRIPE_WEBHOOK_SECRET=None,
    )
    def test_no_webhook_secret_raises_improperly_configured(self):
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesMessage(
                ImproperlyConfigured,
                "PINAX_STRIPE_WEBHOOK_SECRET not set",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
                **self.signature_headers(msg)
            )
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API

    def test_post_without_signature_raises_invalid_signature(self):
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesMessage(
                VerificationError,
                "Missing Stripe-Signature header",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
            )
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API

    def test_post_with_bad_signature_raises_invalid_signature(self):
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesRegexp(
                VerificationError,
                "^SignatureVerificationError: ",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
                **self.signature_headers(msg, secret="invalid")
            )
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API

    @patch("stripe.WebhookSignature.verify_header", return_value=False)
    def test_stripe_verify_header_returning_false_raises_invalid_signature(self, verify_header_mock):
        # The `stripe.WebhookSignature.verify_header` method returns `True`, or
        # raises an exception.  We don't want to silently accept bad signatures
        # if a future stripe update returns `False` instead of raising
        # exceptions.
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesMessage(
                VerificationError,
                "SignatureVerificationError: Unverified webhook signature",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
                **self.signature_headers(msg, secret="invalid")
            )
        verify_header_mock.assert_called_once()
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API

    def test_post_with_stale_timestamp_raises_invalid_signature(self):
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesRegexp(
                VerificationError,
                "^SignatureVerificationError: ",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
                **self.signature_headers(msg, timestamp=1)
            )
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API

    def test_post_without_signature_returns_400_bad_request(self):
        msg = json.dumps(self.event_data)
        with self.assertNumQueries(0):  # don't DoS the database
            self.assertRaisesRegexp(
                VerificationError,
                "^SignatureVerificationError: ",
                self.post_webhook,
                reverse("pinax_stripe_webhook"),
                six.u(msg),
                content_type="application/json",
                **self.signature_headers(msg, secret="invalid")
            )
        self.stripe_object_request_mock.assert_not_called()  # don't DoS the Stripe API


class ChargeWebhookTest(TestCase):

    @patch("stripe.Charge.retrieve")
    @patch("pinax.stripe.actions.charges.sync_charge_from_stripe_data")
    def test_process_webhook(self, SyncMock, RetrieveMock):
        event = Event.objects.create(kind=ChargeCapturedWebhook.name, webhook_message={}, valid=True, processed=False)
        event.validated_message = dict(data=dict(object=dict(id=1)))
        ChargeCapturedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)
        _, kwargs = RetrieveMock.call_args
        self.assertEquals(kwargs["expand"], ["balance_transaction"])
        self.assertEquals(kwargs["stripe_account"], None)

    @patch("stripe.Charge.retrieve")
    @patch("pinax.stripe.actions.charges.sync_charge_from_stripe_data")
    def test_process_webhook_connect(self, SyncMock, RetrieveMock):
        account = Account.objects.create(stripe_id="acc_A")
        event = Event.objects.create(kind=ChargeCapturedWebhook.name, webhook_message={}, valid=True, processed=False, stripe_account=account)
        event.validated_message = dict(data=dict(object=dict(id=1)))
        ChargeCapturedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)
        _, kwargs = RetrieveMock.call_args
        self.assertEquals(kwargs["expand"], ["balance_transaction"])
        self.assertEquals(kwargs["stripe_account"], "acc_A")


class CustomerDeletedWebhookTest(TestCase):

    def test_process_webhook_without_linked_customer(self):
        event = Event.objects.create(kind=CustomerDeletedWebhook.name, webhook_message={}, valid=True, processed=False)
        CustomerDeletedWebhook(event).process_webhook()

    def test_process_webhook_with_linked_customer(self):
        User = get_user_model()
        customer = Customer.objects.create(user=User.objects.create())
        self.assertIsNotNone(customer.user)
        event = Event.objects.create(kind=CustomerDeletedWebhook.name, webhook_message={}, valid=True, processed=False, customer=customer)
        CustomerDeletedWebhook(event).process_webhook()
        self.assertIsNone(customer.user)


class CustomerUpdatedWebhookTest(TestCase):

    @patch("pinax.stripe.actions.customers.sync_customer")
    def test_process_webhook_without_customer(self, SyncMock):
        event = Event.objects.create(kind=CustomerUpdatedWebhook.name, webhook_message={}, valid=True, processed=False)
        CustomerUpdatedWebhook(event).process_webhook()
        self.assertEquals(SyncMock.call_count, 0)

    @patch("pinax.stripe.actions.customers.sync_customer")
    def test_process_webhook_without_customer_with_data(self, SyncMock):
        event = Event.objects.create(kind=CustomerUpdatedWebhook.name, webhook_message={}, valid=True, processed=False)
        obj = object()
        event.validated_message = dict(data=dict(object=obj))
        CustomerUpdatedWebhook(event).process_webhook()
        self.assertEquals(SyncMock.call_count, 0)

    @patch("pinax.stripe.actions.customers.sync_customer")
    def test_process_webhook_with_customer_with_data(self, SyncMock):
        customer = Customer.objects.create()
        event = Event.objects.create(kind=CustomerUpdatedWebhook.name, customer=customer, webhook_message={}, valid=True, processed=False)
        obj = object()
        event.validated_message = dict(data=dict(object=obj))
        CustomerUpdatedWebhook(event).process_webhook()
        self.assertEquals(SyncMock.call_count, 1)
        self.assertIs(SyncMock.call_args[0][0], customer)
        self.assertIs(SyncMock.call_args[0][1], obj)


class CustomerSourceCreatedWebhookTest(TestCase):

    @patch("pinax.stripe.actions.sources.sync_payment_source_from_stripe_data")
    def test_process_webhook(self, SyncMock):
        event = Event.objects.create(kind=CustomerSourceCreatedWebhook.name, webhook_message={}, valid=True, processed=False)
        event.validated_message = dict(data=dict(object=dict()))
        CustomerSourceCreatedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)


class CustomerSourceDeletedWebhookTest(TestCase):

    @patch("pinax.stripe.actions.sources.delete_card_object")
    def test_process_webhook(self, SyncMock):
        event = Event.objects.create(kind=CustomerSourceDeletedWebhook.name, webhook_message={}, valid=True, processed=False)
        event.validated_message = dict(data=dict(object=dict(id=1)))
        CustomerSourceDeletedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)


class PlanCreatedWebhookTest(TestCase):

    @patch("stripe.Event.retrieve")
    def test_plan_created(self, EventMock):
        ev = EventMock()
        ev.to_dict.return_value = PLAN_CREATED_TEST_DATA
        event = Event.objects.create(
            stripe_id=PLAN_CREATED_TEST_DATA["id"],
            kind="plan.created",
            livemode=True,
            webhook_message=PLAN_CREATED_TEST_DATA,
            validated_message=PLAN_CREATED_TEST_DATA,
            valid=True
        )
        registry.get(event.kind)(event).process()
        self.assertEquals(Plan.objects.all().count(), 1)


class PlanUpdatedWebhookTest(TestCase):

    @patch("stripe.Event.retrieve")
    def test_plan_created(self, EventMock):
        Plan.objects.create(
            stripe_id="gold1",
            name="Gold Plan",
            interval="month",
            interval_count=1,
            amount=decimal.Decimal("9.99")
        )
        ev = EventMock()
        ev.to_dict.return_value = PLAN_CREATED_TEST_DATA
        event = Event.objects.create(
            stripe_id=PLAN_CREATED_TEST_DATA["id"],
            kind="plan.updated",
            livemode=True,
            webhook_message=PLAN_CREATED_TEST_DATA,
            validated_message=PLAN_CREATED_TEST_DATA,
            valid=True
        )
        registry.get(event.kind)(event).process()
        plan = Plan.objects.get(stripe_id="gold1")
        self.assertEquals(plan.name, PLAN_CREATED_TEST_DATA["data"]["object"]["name"])


class CustomerSubscriptionCreatedWebhookTest(TestCase):

    @patch("pinax.stripe.actions.subscriptions.sync_subscription_from_stripe_data")
    @patch("pinax.stripe.actions.customers.sync_customer")
    def test_process_webhook(self, SyncMock, SubSyncMock):
        event = Event.objects.create(
            kind=CustomerSubscriptionCreatedWebhook.name,
            customer=Customer.objects.create(),
            validated_message={"data": {"object": {}}},
            valid=True,
            processed=False)
        CustomerSubscriptionCreatedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)
        self.assertTrue(SubSyncMock.called)

    @patch("pinax.stripe.actions.subscriptions.sync_subscription_from_stripe_data")
    @patch("pinax.stripe.actions.customers.sync_customer")
    def test_process_webhook_no_customer(self, SyncMock, SubSyncMock):
        event = Event.objects.create(
            kind=CustomerSubscriptionCreatedWebhook.name,
            validated_message={"data": {"object": {}}},
            valid=True,
            processed=False)
        CustomerSubscriptionCreatedWebhook(event).process_webhook()
        self.assertFalse(SyncMock.called)
        self.assertTrue(SubSyncMock.called)


class CustomerSubscriptionUpdatedWebhookTest(TestCase):

    WEBHOOK_MESSAGE_DATA = {
        "object": {"livemode": False}
    }

    VALIDATED_MESSAGE_DATA = {
        "previous_attributes": {"days_until_due": 30, "billing": "send_invoice"},
        "object": {"livemode": False}
    }

    VALIDATED_MESSAGE_DATA_NOT_VALID = {
        "previous_attributes": {"days_until_due": 30, "billing": "send_invoice"},
        "object": {"livemode": True}
    }

    def test_is_event_valid_yes(self):
        self.assertTrue(Webhook.is_event_valid(self.WEBHOOK_MESSAGE_DATA, self.VALIDATED_MESSAGE_DATA))

    def test_is_event_valid_no(self):
        self.assertFalse(Webhook.is_event_valid(self.WEBHOOK_MESSAGE_DATA, self.VALIDATED_MESSAGE_DATA_NOT_VALID))


class InvoiceCreatedWebhookTest(TestCase):

    @patch("pinax.stripe.actions.invoices.sync_invoice_from_stripe_data")
    def test_process_webhook(self, SyncMock):
        event = Event.objects.create(kind=InvoiceCreatedWebhook.name, webhook_message={}, valid=True, processed=False)
        event.validated_message = dict(data=dict(object=dict(id=1)))
        InvoiceCreatedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)


class TestTransferWebhooks(TestCase):

    @patch("stripe.Event.retrieve")
    @patch("stripe.Transfer.retrieve")
    def test_transfer_created(self, TransferMock, EventMock):
        ev = EventMock()
        ev.to_dict.return_value = TRANSFER_CREATED_TEST_DATA
        TransferMock.return_value = TRANSFER_CREATED_TEST_DATA["data"]["object"]
        event = Event.objects.create(
            stripe_id=TRANSFER_CREATED_TEST_DATA["id"],
            kind="transfer.created",
            livemode=True,
            webhook_message=TRANSFER_CREATED_TEST_DATA,
            validated_message=TRANSFER_CREATED_TEST_DATA,
            valid=True
        )
        registry.get(event.kind)(event).process()
        transfer = Transfer.objects.get(stripe_id="tr_XXXXXXXXXXXX")
        self.assertEquals(transfer.amount, decimal.Decimal("4.55"))
        self.assertEquals(transfer.status, "paid")

    @patch("stripe.Event.retrieve")
    @patch("stripe.Transfer.retrieve")
    def test_transfer_pending_create(self, TransferMock, EventMock):
        ev = EventMock()
        ev.to_dict.return_value = TRANSFER_PENDING_TEST_DATA
        TransferMock.return_value = TRANSFER_PENDING_TEST_DATA["data"]["object"]
        event = Event.objects.create(
            stripe_id=TRANSFER_PENDING_TEST_DATA["id"],
            kind="transfer.created",
            livemode=True,
            webhook_message=TRANSFER_PENDING_TEST_DATA,
            validated_message=TRANSFER_PENDING_TEST_DATA,
            valid=True
        )
        registry.get(event.kind)(event).process()
        transfer = Transfer.objects.get(stripe_id="tr_adlkj2l3kj23")
        self.assertEquals(transfer.amount, decimal.Decimal("9.41"))
        self.assertEquals(transfer.status, "pending")

    @patch("stripe.Event.retrieve")
    @patch("stripe.Transfer.retrieve")
    def test_transfer_paid_updates_existing_record(self, TransferMock, EventMock):
        ev = EventMock()
        ev.to_dict.return_value = TRANSFER_CREATED_TEST_DATA
        TransferMock.return_value = TRANSFER_CREATED_TEST_DATA["data"]["object"]
        event = Event.objects.create(
            stripe_id=TRANSFER_CREATED_TEST_DATA["id"],
            kind="transfer.created",
            livemode=True,
            webhook_message=TRANSFER_CREATED_TEST_DATA,
            validated_message=TRANSFER_CREATED_TEST_DATA,
            valid=True
        )
        registry.get(event.kind)(event).process()
        data = {
            "created": 1364658818,
            "data": {
                "object": {
                    "account": {
                        "bank_name": "BANK OF AMERICA, N.A.",
                        "country": "US",
                        "last4": "9999",
                        "object": "bank_account"
                    },
                    "amount": 455,
                    "currency": "usd",
                    "date": 1364601600,
                    "description": "STRIPE TRANSFER",
                    "fee": 0,
                    "fee_details": [],
                    "id": "tr_XXXXXXXXXXXX",
                    "livemode": True,
                    "object": "transfer",
                    "other_transfers": [],
                    "status": "paid",
                    "summary": {
                        "adjustment_count": 0,
                        "adjustment_fee_details": [],
                        "adjustment_fees": 0,
                        "adjustment_gross": 0,
                        "charge_count": 1,
                        "charge_fee_details": [{
                            "amount": 45,
                            "application": None,
                            "currency": "usd",
                            "description": None,
                            "type": "stripe_fee"
                        }],
                        "charge_fees": 45,
                        "charge_gross": 500,
                        "collected_fee_count": 0,
                        "collected_fee_gross": 0,
                        "collected_fee_refund_count": 0,
                        "collected_fee_refund_gross": 0,
                        "currency": "usd",
                        "net": 455,
                        "refund_count": 0,
                        "refund_fee_details": [],
                        "refund_fees": 0,
                        "refund_gross": 0,
                        "validation_count": 0,
                        "validation_fees": 0
                    },
                    "transactions": {
                        "count": 1,
                        "data": [{
                            "amount": 500,
                            "created": 1364064631,
                            "description": None,
                            "fee": 45,
                            "fee_details": [{
                                "amount": 45,
                                "application": None,
                                "currency": "usd",
                                "description": "Stripe processing fees",
                                "type": "stripe_fee"
                            }],
                            "id": "ch_XXXXXXXXXX",
                            "net": 455,
                            "type": "charge"
                        }],
                        "object": "list",
                        "url": "/v1/transfers/XX/transactions"
                    }
                }
            },
            "id": "evt_YYYYYYYYYYYY",
            "livemode": True,
            "object": "event",
            "pending_webhooks": 1,
            "type": "transfer.paid"
        }
        paid_event = Event.objects.create(
            stripe_id=data["id"],
            kind="transfer.paid",
            livemode=True,
            webhook_message=data,
            validated_message=data,
            valid=True
        )
        registry.get(paid_event.kind)(paid_event).process()
        transfer = Transfer.objects.get(stripe_id="tr_XXXXXXXXXXXX")
        self.assertEquals(transfer.status, "paid")


class AccountWebhookTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super(AccountWebhookTest, cls).setUpClass()
        cls.account = Account.objects.create(stripe_id="acc_aa")

    @patch("stripe.Account.retrieve")
    @patch("pinax.stripe.actions.accounts.sync_account_from_stripe_data")
    def test_process_webhook(self, SyncMock, RetrieveMock):
        event = Event.objects.create(
            kind=AccountUpdatedWebhook.name,
            webhook_message={},
            valid=True,
            processed=False
        )
        event.validated_message = dict(data=dict(object=dict(id=1)))
        AccountUpdatedWebhook(event).process_webhook()
        self.assertTrue(SyncMock.called)

    @patch("stripe.Event.retrieve")
    def test_process_deauthorize(self, RetrieveMock):
        data = {"data": {"object": {"id": "evt_001"}},
                "account": self.account.stripe_id}
        event = Event.objects.create(
            kind=AccountApplicationDeauthorizeWebhook.name,
            webhook_message=data,
        )
        RetrieveMock.side_effect = stripe.error.PermissionError(
            "The provided key 'sk_test_********************abcd' does not have access to account 'acc_aa' (or that account does not exist). Application access may have been revoked.")
        AccountApplicationDeauthorizeWebhook(event).process()
        self.assertTrue(event.valid)
        self.assertTrue(event.processed)
        self.account.refresh_from_db()
        self.assertFalse(self.account.authorized)

    @patch("stripe.Event.retrieve")
    def test_process_deauthorize_fake_response(self, RetrieveMock):
        data = {"data": {"object": {"id": "evt_001"}},
                "account": self.account.stripe_id}
        event = Event.objects.create(
            kind=AccountApplicationDeauthorizeWebhook.name,
            webhook_message=data,
        )
        RetrieveMock.side_effect = stripe.error.PermissionError(
            "The provided key 'sk_test_********************ABCD' does not have access to account 'acc_aa' (or that account does not exist). Application access may have been revoked.")
        with self.assertRaises(stripe.error.PermissionError):
            AccountApplicationDeauthorizeWebhook(event).process()

    @patch("stripe.Event.retrieve")
    def test_process_deauthorize_with_delete_account(self, RetrieveMock):
        data = {"data": {"object": {"id": "evt_002"}},
                "account": "acct_bb"}
        event = Event.objects.create(
            kind=AccountApplicationDeauthorizeWebhook.name,
            webhook_message=data,
        )
        RetrieveMock.side_effect = stripe.error.PermissionError(
            "The provided key 'sk_test_********************abcd' does not have access to account 'acct_bb' (or that account does not exist). Application access may have been revoked.")
        AccountApplicationDeauthorizeWebhook(event).process()
        self.assertTrue(event.valid)
        self.assertTrue(event.processed)
        self.assertIsNone(event.stripe_account)

    @patch("stripe.Event.retrieve")
    def test_process_deauthorize_without_account(self, RetrieveMock):
        data = {"data": {"object": {"id": "evt_001"}}}
        event = Event.objects.create(
            kind=AccountApplicationDeauthorizeWebhook.name,
            webhook_message=data,
        )
        RetrieveMock.return_value.to_dict.return_value = data
        AccountApplicationDeauthorizeWebhook(event).process()
        self.assertTrue(event.valid)
        self.assertTrue(event.processed)
        self.account.refresh_from_db()
        self.assertTrue(self.account.authorized)
