"""Unit tests for the enforcement module — validate_transition_date function."""

import pytest

from scripts.enforcement import validate_transition_date


class TestValidateTransitionDate:
    """Tests for validate_transition_date scheduling logic."""

    # --- Valid cases (>= 5 business days) ---

    def test_exactly_5_business_days_weekdays_only(self):
        """Mon notification, next Mon transition = 5 business days (Tue-Sat? No, Tue-Fri=4, Mon=5 wait...)
        Actually: notification=Mon 2025-01-06, transition=Mon 2025-01-13
        Days between (exclusive both): Tue(7), Wed(8), Thu(9), Fri(10), [Sat,Sun skip], Mon? No, Mon is end.
        Wait — between 6th (exclusive) and 13th (exclusive): 7,8,9,10 (4 biz days) + no more.
        Need to go further: notification=Mon Jan 6, transition=Tue Jan 14
        Between: 7(T),8(W),9(Th),10(F),11(Sa),12(Su),13(M) = 5 biz days. Yes!
        """
        # 2025-01-06 is Monday, 2025-01-14 is Tuesday
        # Business days between (exclusive): Jan 7(T),8(W),9(Th),10(F),13(M) = 5
        valid, msg = validate_transition_date("2025-01-14", "2025-01-06")
        assert valid is True
        assert "5 business days" in msg

    def test_more_than_5_business_days(self):
        """Plenty of notice — 10 business days."""
        # 2025-01-06 (Mon) to 2025-01-22 (Wed) = 11 biz days between
        valid, msg = validate_transition_date("2025-01-22", "2025-01-06")
        assert valid is True
        assert "business days" in msg

    def test_7_calendar_days_with_weekend(self):
        """Friday notification, next Friday transition = 5 biz days."""
        # 2025-01-10 is Friday, 2025-01-17 is Friday
        # Between (exclusive): Mon(13),Tue(14),Wed(15),Thu(16) = 4 biz days
        # Not quite 5. Let's use Mon 2025-01-20:
        # Between Fri 10 and Mon 20 (exclusive): Mon(13),Tue(14),Wed(15),Thu(16),Fri(17) = 5
        valid, msg = validate_transition_date("2025-01-20", "2025-01-10")
        assert valid is True
        assert "5 business days" in msg

    # --- Invalid cases (< 5 business days) ---

    def test_insufficient_notice_3_business_days(self):
        """Only 3 business days of notice."""
        # 2025-01-06 (Mon) to 2025-01-09 (Thu)
        # Between: Tue(7), Wed(8) = 2 biz days. Hmm, let me recalculate.
        # Between Mon 6 (excl) and Thu 9 (excl): Tue(7), Wed(8) = 2 biz days
        valid, msg = validate_transition_date("2025-01-09", "2025-01-06")
        assert valid is False
        assert "only 2 business days" in msg

    def test_insufficient_notice_weekend_in_between(self):
        """Thursday notification, next Monday transition = only 1 biz day."""
        # 2025-01-09 (Thu) to 2025-01-13 (Mon)
        # Between Thu 9 (excl) and Mon 13 (excl): Fri(10) = 1 biz day
        valid, msg = validate_transition_date("2025-01-13", "2025-01-09")
        assert valid is False
        assert "only 1 business days" in msg

    def test_zero_business_days_adjacent(self):
        """Notification on Friday, transition on Monday = 0 biz days between."""
        # 2025-01-10 (Fri) to 2025-01-13 (Mon)
        # Between Fri 10 (excl) and Mon 13 (excl): Sat(11), Sun(12) = 0 biz days
        valid, msg = validate_transition_date("2025-01-13", "2025-01-10")
        assert valid is False
        assert "only 0 business days" in msg

    def test_next_day_transition(self):
        """Transition is the very next day — 0 business days."""
        # 2025-01-13 (Mon) to 2025-01-14 (Tue)
        # Between Mon 13 (excl) and Tue 14 (excl): nothing = 0 biz days
        valid, msg = validate_transition_date("2025-01-14", "2025-01-13")
        assert valid is False
        assert "only 0 business days" in msg

    # --- Transition date in the past ---

    def test_transition_date_in_past(self):
        """Transition date before notification date."""
        valid, msg = validate_transition_date("2025-01-01", "2025-01-10")
        assert valid is False
        assert "in the past" in msg

    def test_transition_date_same_as_notification(self):
        """Transition date equals notification date — treated as past."""
        valid, msg = validate_transition_date("2025-01-10", "2025-01-10")
        assert valid is False
        assert "in the past" in msg

    # --- Invalid date formats ---

    def test_invalid_transition_date_format(self):
        """Non-ISO format for transition date."""
        valid, msg = validate_transition_date("01/15/2025", "2025-01-06")
        assert valid is False
        assert "not a valid ISO 8601 date" in msg

    def test_invalid_notification_date_format(self):
        """Non-ISO format for notification date."""
        valid, msg = validate_transition_date("2025-01-15", "Jan 6 2025")
        assert valid is False
        assert "not a valid ISO 8601 date" in msg

    def test_empty_transition_date(self):
        """Empty string for transition date."""
        valid, msg = validate_transition_date("", "2025-01-06")
        assert valid is False
        assert "not a valid ISO 8601 date" in msg

    def test_none_notification_date_uses_today(self):
        """When notification_date is None, defaults to today."""
        # Use a date far in the future to ensure it's valid
        valid, msg = validate_transition_date("2099-12-31", None)
        assert valid is True
        assert "business days" in msg

    def test_garbage_transition_date(self):
        """Completely invalid string."""
        valid, msg = validate_transition_date("not-a-date", "2025-01-06")
        assert valid is False
        assert "not a valid ISO 8601 date" in msg

    # --- Weekend handling ---

    def test_two_weekends_between(self):
        """Two weekends between notification and transition — still enough."""
        # 2025-01-06 (Mon) to 2025-01-20 (Mon)
        # Between: 7(T),8(W),9(Th),10(F),13(M),14(T),15(W),16(Th),17(F) = 9 biz days
        valid, msg = validate_transition_date("2025-01-20", "2025-01-06")
        assert valid is True
        assert "9 business days" in msg

    def test_notification_on_saturday(self):
        """Notification sent on Saturday — weekend days after don't count."""
        # 2025-01-11 (Sat) to 2025-01-20 (Mon)
        # Between Sat 11 (excl) and Mon 20 (excl):
        # Sun(12), Mon(13), Tue(14), Wed(15), Thu(16), Fri(17), Sat(18), Sun(19)
        # Biz days: 13,14,15,16,17 = 5
        valid, msg = validate_transition_date("2025-01-20", "2025-01-11")
        assert valid is True
        assert "5 business days" in msg
