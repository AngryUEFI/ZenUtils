import pytest
from arch.eval import ConditionEvaluator

def test_eval():
    fields = {'foo': {'value': 1}, 'bar': {'value': 2000}}
    evaluator = ConditionEvaluator(fields)
    assert evaluator.evaluate("foo < 10 && bar == 2000")
    assert evaluator.evaluate("(foo < 10 || foor >= 20) && bar == 2000")
    assert not evaluator.evaluate("foo > 10")

def test_extract():
    valid = "operation == 0xa0 && imm_mode == 1"
    extracted = ConditionEvaluator.extract_defs_from_condition(valid)
    assert len(extracted) == 2
    assert extracted['operation'] == 0xa0
    assert extracted['imm_mode'] == 1

    # For extraction only expr of the form 'var == val [&& var_n == val_n]*' are allowed
    invalid_form = "operation == 0xa0 || imm_mode == 1"
    form_error_occured = False
    try:
        extracted = ConditionEvaluator.extract_defs_from_condition(invalid_form)
    except ValueError as e:
        form_error_occured = True

    assert form_error_occured

    # For extraction each variable may only occur once
    invalid_multi_var = "operation == 0xa0 && operation == 1"
    multi_var_error_occured = False
    try:
        extracted = ConditionEvaluator.extract_defs_from_condition(invalid_multi_var)
    except ValueError as e:
        multi_var_error_occured = True

    assert multi_var_error_occured